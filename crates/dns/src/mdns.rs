//! Multicast DNS library for futures.

use std::{
    collections::VecDeque,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};

use futures::{lock::Mutex, Stream};
use futures_map::KeyWaitMap;
use hickory_proto::{
    op::{Message, MessageType, Query},
    rr::{rdata::NULL, Name, Record, RecordData, RecordType},
};
use uuid::Uuid;

use crate::{Error, Result};

/// Multicast ipv4 for mdns
pub const MULTICAST_ADDR_IPV4: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);

/// Multicast ipv6 address for mdns
pub const MULTICAST_ADDR_IPV6: Ipv6Addr = Ipv6Addr::new(0xFF02, 0, 0, 0, 0, 0, 0, 0x0123);

/// Multicast port for mdns.
pub const MULTICAST_PORT: u16 = 5353;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum MdnsDiscoverEvent {
    Send,
    Receive,
}

#[derive(Default)]
struct RawMdnsDiscoverMutable {
    incoming: VecDeque<(Message, SocketAddr)>,
    outgoing: VecDeque<Vec<u8>>,
    last_asking: Option<Instant>,
}

struct RawMdnsDiscover {
    is_closed: spin::Mutex<bool>,
    id: Name,
    service_name: Name,
    intervals: Duration,
    mutable: Mutex<RawMdnsDiscoverMutable>,
    event_map: KeyWaitMap<MdnsDiscoverEvent, ()>,
}

impl RawMdnsDiscover {
    fn new(service_name: &str, intervals: Duration) -> Result<Self> {
        Ok(Self {
            id: Name::from_utf8(format!("{}.futures-dns.mdns", Uuid::new_v4()))?,
            is_closed: Default::default(),
            service_name: Name::from_utf8(service_name)?,
            intervals,
            mutable: Default::default(),
            event_map: Default::default(),
        })
    }
}

/// The network api of [`MdnsDiscover`]
#[derive(Clone)]
pub struct MdnsDiscoverNetwork(Arc<RawMdnsDiscover>);

impl MdnsDiscoverNetwork {
    /// Create new discover instance with `service_name` and with asking `intervals`.
    fn new<S>(service_name: S, intervals: Duration) -> Result<Self>
    where
        S: AsRef<str>,
    {
        Ok(Self(Arc::new(RawMdnsDiscover::new(
            service_name.as_ref(),
            intervals,
        )?)))
    }

    /// Close this state.
    pub fn close(&self) {
        *self.0.is_closed.lock() = true;

        self.0.event_map.batch_insert([
            (MdnsDiscoverEvent::Send, ()),
            (MdnsDiscoverEvent::Receive, ()),
        ]);
    }

    pub async fn is_closed(&self) {
        loop {
            let is_closed = self.0.is_closed.lock();
            if *is_closed {
                return;
            }

            self.0
                .event_map
                .wait(&MdnsDiscoverEvent::Send, is_closed)
                .await;
        }
    }

    /// Process generating a new query packet.
    pub async fn on_timeout(&self) -> Result<()> {
        if *self.0.is_closed.lock() {
            return Err(Error::InvalidState);
        }

        let mut message = Message::new();

        message
            .set_id(rand::random())
            .set_message_type(MessageType::Query)
            .add_query(Query::query(self.0.service_name.clone(), RecordType::PTR));

        self.multicast(message).await?;

        self.0.mutable.lock().await.last_asking = Some(Instant::now());

        Ok(())
    }

    /// Returns when the next timeout event will occur.
    pub async fn timeout_instant(&self) -> Option<Instant> {
        if *self.0.is_closed.lock() {
            return None;
        }

        let mutable = self.0.mutable.lock().await;

        if let Some(last_asking) = mutable.last_asking {
            Some(last_asking + self.0.intervals)
        } else {
            Some(Instant::now())
        }
    }

    /// Multicast provides DNS `message`.
    pub async fn multicast(&self, mut message: Message) -> Result<()> {
        if *self.0.is_closed.lock() {
            return Err(Error::InvalidState);
        }

        message.add_additional(Record::from_rdata(
            self.0.id.clone(),
            0,
            NULL::new().into_rdata(),
        ));

        self.0
            .mutable
            .lock()
            .await
            .outgoing
            .push_back(message.to_vec()?);

        self.0.event_map.insert(MdnsDiscoverEvent::Send, ());

        Ok(())
    }

    /// Writes a single DNS packet to be multicast.
    pub async fn send(&self) -> Result<Vec<u8>> {
        loop {
            if *self.0.is_closed.lock() {
                return Err(Error::InvalidState);
            }

            let mut mutable = self.0.mutable.lock().await;

            if let Some(message) = mutable.outgoing.pop_front() {
                return Ok(message);
            }

            self.0
                .event_map
                .wait(&MdnsDiscoverEvent::Send, mutable)
                .await;
        }
    }

    /// Processes DNS packet received from the multicast address.
    pub async fn recv<Buf>(&self, buf: Buf, from: SocketAddr) -> Result<()>
    where
        Buf: AsRef<[u8]>,
    {
        let message = Message::from_vec(buf.as_ref())?;

        if message
            .additionals()
            .iter()
            .any(|record| record.name().eq(&self.0.id))
        {
            log::warn!("skip packet that sent by self: {}", from);
            return Ok(());
        }

        if !message.answers().iter().any(|record| {
            log::trace!("server_name: {}", record.name());
            record.name().eq(&self.0.service_name)
        }) {
            log::warn!("skip response from {}, unexpect server_names.", from);
            return Ok(());
        }

        self.0
            .mutable
            .lock()
            .await
            .incoming
            .push_back((message, from));

        self.0.event_map.insert(MdnsDiscoverEvent::Receive, ());

        Ok(())
    }
}

/// Returns by [`send`](MdnsDiscover::send) function.
pub enum MdnsDiscoverSend {
    Buf(Vec<u8>),
    Sleep(Duration),
}

/// Utilities for discovering devices on the LAN
pub struct MdnsDiscover(MdnsDiscoverNetwork);

impl Drop for MdnsDiscover {
    fn drop(&mut self) {
        self.0.close();
    }
}

impl MdnsDiscover {
    /// Create new discover instance with `service_name` and with asking `intervals`.
    pub fn new<S>(service_name: S, intervals: Duration) -> Result<Self>
    where
        S: AsRef<str>,
    {
        Ok(Self(MdnsDiscoverNetwork::new(service_name, intervals)?))
    }

    /// Returns an inner [`MdnsDiscoverNetwork`] instance.
    pub fn to_network(&self) -> MdnsDiscoverNetwork {
        self.0.clone()
    }

    /// Accept a new incoming mdns response.
    pub async fn accept(&self) -> Result<(Message, SocketAddr)> {
        loop {
            if *self.0 .0.is_closed.lock() {
                return Err(Error::InvalidState);
            }

            let mut mutable = self.0 .0.mutable.lock().await;

            if let Some(message) = mutable.incoming.pop_front() {
                return Ok(message);
            }

            self.0
                 .0
                .event_map
                .wait(&MdnsDiscoverEvent::Receive, mutable)
                .await;
        }
    }

    /// Conver [`MdnsDiscover`] into a [`Stream`].
    pub fn into_incoming(self) -> impl Stream<Item = Result<(Message, SocketAddr)>> + Unpin {
        Box::pin(futures::stream::unfold(self, |listener| async move {
            let res = listener.accept().await;
            Some((res, listener))
        }))
    }
}
