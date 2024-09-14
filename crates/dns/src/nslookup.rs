//! This module provides a asynchronously DNS client implementation.

use std::{
    collections::VecDeque,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    str::from_utf8,
    sync::{
        atomic::{AtomicBool, AtomicU16, Ordering},
        Arc,
    },
};

use futures::lock::Mutex;
use futures_map::KeyWaitMap;
use hickory_proto::{
    op::{Message, MessageType, Query, ResponseCode},
    rr::{Name, RData, RecordType},
};

use crate::errors::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum LookupEvent {
    Send,
    Response(u16),
}

enum LookupEventArg {
    Send,
    Response(Vec<u8>),
}

#[derive(Default)]
pub(crate) struct RawDnsLookup {
    is_closed: AtomicBool,
    idgen: AtomicU16,
    sending: Mutex<VecDeque<Vec<u8>>>,
    waiters: KeyWaitMap<LookupEvent, LookupEventArg>,
}

/// A DNS client type without [`Drop`] support.
/// you should manually call the [`close`](DnsLookupState::close) function to cleanup resources.
///
/// Usually this type is used by background io tasks, the end-users should use [`DnsLookup`] instead.
#[derive(Default, Clone)]
pub struct DnsLookupNetwork(pub(crate) Arc<RawDnsLookup>);

impl DnsLookupNetwork {
    /// Returns true if this client is closed.
    pub fn is_closed(&self) -> bool {
        self.0.is_closed.load(Ordering::SeqCst)
    }

    /// Writes a single DNS packet to be sent to the server.
    pub async fn send(&self) -> Result<Vec<u8>> {
        loop {
            if let Some(buf) = self.0.sending.lock().await.pop_front() {
                return Ok(buf);
            }

            if self.0.is_closed.load(Ordering::SeqCst) {
                return Err(Error::InvalidState);
            }

            self.0.waiters.wait(&LookupEvent::Send, ()).await;
        }
    }

    /// Processes DNS packet received from the peer.
    pub async fn recv<Buf>(&self, buf: Buf) -> Result<()>
    where
        Buf: AsRef<[u8]>,
    {
        if self.0.is_closed.load(Ordering::SeqCst) {
            return Err(Error::InvalidState);
        }

        // Incomplete packet.
        if buf.as_ref().len() < 12 {
            return Err(Error::TooShort);
        }

        let mut id_buf = [0; 2];

        id_buf.copy_from_slice(&buf.as_ref()[..2]);

        let id = u16::from_be_bytes(id_buf);

        self.0.waiters.insert(
            LookupEvent::Response(id),
            LookupEventArg::Response(buf.as_ref().to_vec()),
        );

        Ok(())
    }

    /// Close this client
    pub fn close(&self) {
        self.0.is_closed.store(true, Ordering::SeqCst);

        self.0
            .waiters
            .insert(LookupEvent::Send, LookupEventArg::Send);
    }
}

/// A asynchronous DNs client.
#[derive(Default)]
pub struct DnsLookup(DnsLookupNetwork);

impl Drop for DnsLookup {
    fn drop(&mut self) {
        self.0.close();
    }
}

impl DnsLookup {
    fn parse_ip_addrs<'a>(message: &Message) -> Result<Vec<IpAddr>> {
        let mut group = vec![];

        for answer in message.answers() {
            if let Some(data) = answer.data() {
                match data {
                    RData::A(a) => {
                        log::trace!("{} has addr {}", answer.name(), a.0);
                        group.push(a.0.clone().into());
                    }
                    RData::AAAA(aaa) => {
                        log::trace!("{} has addr {}", answer.name(), aaa.0);
                        group.push(aaa.0.clone().into());
                    }
                    _ => {}
                }
            }
        }

        Ok(group)
    }

    fn parse_txt<'a, 'b>(message: &Message) -> Result<Vec<String>> {
        let mut group = vec![];

        for answer in message.answers() {
            if let Some(data) = answer.data() {
                match data {
                    RData::TXT(txt) => {
                        let txt = txt
                            .iter()
                            .map(|x| from_utf8(x).map_err(|err| err.into()))
                            .collect::<Result<Vec<_>>>()?
                            .concat();
                        log::trace!("{} has txt {}", answer.name(), txt);
                        group.push(txt);
                    }

                    _ => {}
                }
            }
        }

        Ok(group)
    }
}

impl DnsLookup {
    /// Get the innner [`DnsLookupState`] instance.
    pub fn to_network(&self) -> DnsLookupNetwork {
        self.0.clone()
    }
    /// Lookup ipv6 records.
    pub async fn lookup_ipv6<N>(&self, label: N) -> Result<Vec<Ipv6Addr>>
    where
        N: AsRef<str>,
    {
        self.call_with(label.as_ref(), &[RecordType::AAAA], Self::parse_ip_addrs)
            .await
            .map(|addrs| {
                addrs
                    .into_iter()
                    .filter_map(|addr| match addr {
                        IpAddr::V6(addr) => Some(addr),
                        IpAddr::V4(_) => None,
                    })
                    .collect()
            })
    }

    /// Lookup ipv4 records.
    pub async fn lookup_ipv4<N>(&self, label: N) -> Result<Vec<Ipv4Addr>>
    where
        N: AsRef<str>,
    {
        self.call_with(label.as_ref(), &[RecordType::A], Self::parse_ip_addrs)
            .await
            .map(|addrs| {
                addrs
                    .into_iter()
                    .filter_map(|addr| match addr {
                        IpAddr::V4(addr) => Some(addr),
                        IpAddr::V6(_) => None,
                    })
                    .collect()
            })
    }
    /// Lookup ipv4/ipv6 records.
    pub async fn lookup_ip<N>(&self, label: N) -> Result<Vec<IpAddr>>
    where
        N: AsRef<str>,
    {
        let mut addrs_v6 = self
            .call_with(label.as_ref(), &[RecordType::AAAA], Self::parse_ip_addrs)
            .await?;

        let mut addrs_v4 = self
            .call_with(label.as_ref(), &[RecordType::A], Self::parse_ip_addrs)
            .await?;

        addrs_v6.append(&mut addrs_v4);

        Ok(addrs_v6)
    }

    /// Lookup txt records.
    pub async fn lookup_txt<N>(&self, label: N) -> Result<Vec<String>>
    where
        N: AsRef<str>,
    {
        self.call_with(label.as_ref(), &[RecordType::TXT], Self::parse_txt)
            .await
    }

    pub async fn call_with<F, R, E>(&self, qname: &str, qtypes: &[RecordType], resp: F) -> Result<R>
    where
        F: FnOnce(&Message) -> std::result::Result<R, E>,
        R: 'static,
        Error: From<E>,
    {
        let id = self.0 .0.idgen.fetch_add(1, Ordering::SeqCst);

        let mut message = Message::new();

        message.set_id(id).set_recursion_desired(true);

        for qtype in qtypes {
            log::trace!("{} add question {:?}", qname, qtype);
            message.add_query(Query::query(Name::from_ascii(qname)?, qtype.clone()));
        }

        log::trace!("\n{}", message);

        let buf = message.to_vec()?;

        self.0 .0.sending.lock().await.push_back(buf);

        self.0
             .0
            .waiters
            .insert(LookupEvent::Send, LookupEventArg::Send);

        if let Some(LookupEventArg::Response(buf)) =
            self.0 .0.waiters.wait(&LookupEvent::Response(id), ()).await
        {
            let message = Message::from_vec(&buf)?;

            if message.message_type() != MessageType::Response {
                return Err(Error::InvalidType(message.message_type()));
            }

            if ResponseCode::NoError != message.response_code() {
                return Err(Error::ServerError(message.response_code()));
            }

            Ok(resp(&message)?)
        } else {
            Err(Error::LookupCanceled(id))
        }
    }
}
