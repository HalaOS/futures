use std::net::SocketAddr;

use rasi::{net::UdpSocket, task::spawn_ok};

use crate::Result;

#[cfg(feature = "nslookup")]
mod nslookup {

    use super::*;

    use crate::nslookup::{DnsLookup, DnsLookupNetwork};

    impl DnsLookup {
        /// Create a DNS lookup with sys-wide DNS name server configuration.
        #[cfg(feature = "sysconf")]
        pub async fn over_udp() -> Result<Self> {
            use crate::sysconf;

            Self::with_udp_server(sysconf::name_server()?).await
        }

        /// Create a DNS lookup over udp socket.
        pub async fn with_udp_server(nameserver: SocketAddr) -> Result<Self> {
            let socket = UdpSocket::bind(if nameserver.is_ipv4() {
                "0.0.0.0:0".parse::<SocketAddr>()?
            } else {
                "[::]:0".parse::<SocketAddr>()?
            })
            .await?;

            let this = Self::default();

            let lookup = this.to_network();

            let lookup_cloned = lookup.clone();
            let socket_cloned = socket.clone();
            let server_cloned = nameserver.clone();

            spawn_ok(async move {
                if let Err(err) =
                    Self::udp_send_loop(&lookup_cloned, &socket_cloned, server_cloned).await
                {
                    log::error!("DnsLookup, stop send loop with error: {}", err);
                } else {
                    log::trace!("DnsLookup, stop send loop.",);
                }

                lookup_cloned.close();
                _ = socket_cloned.shutdown(std::net::Shutdown::Both);
            });

            spawn_ok(async move {
                if let Err(err) = Self::udp_recv_loop(&lookup, &socket, nameserver).await {
                    log::error!("DnsLookup, stop recv loop with error: {}", err);
                } else {
                    log::trace!("DnsLookup, stop recv loop.",);
                }

                lookup.close();
            });

            Ok(this)
        }

        async fn udp_send_loop(
            lookup: &DnsLookupNetwork,
            socket: &UdpSocket,
            server: SocketAddr,
        ) -> Result<()> {
            loop {
                let buf = lookup.send().await?;

                let send_size = socket.send_to(buf, server).await?;

                log::trace!("DnsLookup, send len={} raddr={}", send_size, server);
            }
        }

        async fn udp_recv_loop(
            lookup: &DnsLookupNetwork,
            socket: &UdpSocket,
            server: SocketAddr,
        ) -> Result<()> {
            let mut buf = vec![0; 1024 * 1024];

            log::trace!("DnsLookup, udp listener on {}", socket.local_addr()?);

            loop {
                let (read_size, from) = socket.recv_from(&mut buf).await?;

                if from != server {
                    log::warn!("DnsLookup, recv packet from unknown peer={}", from);
                } else {
                    log::trace!("DnsLookup, recv response len={}", read_size);
                }

                lookup.recv(&buf[..read_size]).await?;
            }
        }
    }
}

#[cfg(feature = "mdns")]
mod mdns {
    use std::{
        net::{IpAddr, Ipv4Addr, SocketAddr},
        time::{Duration, Instant},
    };

    use rasi::{net::UdpSocket, task::spawn_ok, timer::sleep_until};
    use socket2::{Domain, Protocol, Type};

    use crate::{
        mdns::{
            MdnsDiscover, MdnsDiscoverNetwork, MULTICAST_ADDR_IPV4, MULTICAST_ADDR_IPV6,
            MULTICAST_PORT,
        },
        Result,
    };

    impl MdnsDiscover {
        /// listen service response on all interfaces.
        pub async fn all<S>(service_name: S, intervals: Duration) -> Result<Self>
        where
            S: AsRef<str>,
        {
            let socket = socket2::Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;

            socket.set_reuse_address(true)?;

            #[cfg(not(any(target_os = "solaris", target_os = "illumos", target_os = "windows")))]
            socket.set_reuse_port(true)?;

            let socketaddr: SocketAddr = (Ipv4Addr::UNSPECIFIED, MULTICAST_PORT).into();

            socket.bind(&socketaddr.into())?;

            #[cfg(unix)]
            let socket = {
                use std::os::fd::IntoRawFd;

                unsafe { UdpSocket::from_raw_fd(socket.into_raw_fd())? }
            };

            #[cfg(windows)]
            let socket = {
                use std::os::windows::io::IntoRawSocket;

                unsafe { UdpSocket::from_raw_socket(socket.into_raw_socket())? }
            };

            socket.set_multicast_loop_v4(true)?;
            socket.join_multicast_v4(&MULTICAST_ADDR_IPV4, &Ipv4Addr::UNSPECIFIED)?;

            let this = Self::new(service_name, intervals)?;

            spawn_ok(this.to_network().timeout_loop(socket.clone()));
            spawn_ok(this.to_network().recv_loop(socket.clone()));
            spawn_ok(this.to_network().send_loop(socket));

            Ok(this)
        }
    }

    impl MdnsDiscoverNetwork {
        async fn timeout_loop(self, socket: UdpSocket) {
            if let Err(err) = self.timeout_loop_prv().await {
                log::error!("mdns_discover 'timeout_loop' stopped with error: {}", err);
            }

            self.close();
            _ = socket.shutdown(std::net::Shutdown::Both);
        }

        async fn timeout_loop_prv(&self) -> Result<()> {
            while let Some(timeout_instant) = self.timeout_instant().await {
                log::trace!(
                    "timeout: {:?}",
                    timeout_instant.duration_since(Instant::now())
                );
                sleep_until(timeout_instant).await;
                self.on_timeout().await?;
            }

            log::trace!("timeout loop stpped");

            Ok(())
        }

        async fn recv_loop(self, socket: UdpSocket) {
            if let Err(err) = self.recv_loop_prv(&socket).await {
                log::error!("mdns_discover 'recv_loop' stopped with error: {}", err);
            }

            self.close();
            _ = socket.shutdown(std::net::Shutdown::Both);
        }

        async fn recv_loop_prv(&self, socket: &UdpSocket) -> Result<()> {
            let mut buf = vec![0; 9000];
            loop {
                let (recv_len, from) = socket.recv_from(&mut buf).await?;

                log::trace!("mdns recv from {}", from);

                self.recv(&buf[..recv_len], from).await?;
            }
        }

        async fn send_loop(self, socket: UdpSocket) {
            if let Err(err) = self.send_loop_prv(&socket).await {
                log::error!("mdns_discover 'send_loop' stopped with error: {}", err);
            }

            self.close();
            _ = socket.shutdown(std::net::Shutdown::Both);
        }

        async fn send_loop_prv(&self, socket: &UdpSocket) -> Result<()> {
            let laddr = socket.local_addr()?;

            let raddr: IpAddr = if laddr.is_ipv4() {
                MULTICAST_ADDR_IPV4.into()
            } else {
                MULTICAST_ADDR_IPV6.into()
            };

            loop {
                let buf = self.send().await?;
                socket.send_to(buf, (raddr, MULTICAST_PORT)).await?;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{Arc, Once},
        time::Duration,
    };

    use rasi::timer::sleep;
    use rasi_mio::{net::register_mio_network, timer::register_mio_timer};

    use crate::nslookup::DnsLookup;

    fn init() {
        static INIT: Once = Once::new();

        INIT.call_once(|| {
            _ = pretty_env_logger::try_init_timed();

            register_mio_network();
            register_mio_timer();
        });
    }

    #[cfg(all(feature = "nslookup", feature = "rasi", feature = "sysconf"))]
    #[futures_test::test]
    async fn test_udp_lookup() {
        init();

        let inner = {
            let lookup = DnsLookup::over_udp().await.unwrap();

            let group = lookup.lookup_ip("am6.bootstrap.libp2p.io").await.unwrap();

            log::trace!("{:?}", group);

            lookup.to_network()
        };

        sleep(Duration::from_secs(1)).await;

        assert_eq!(Arc::strong_count(&inner.0), 1);
    }

    #[cfg(all(feature = "nslookup", feature = "rasi", feature = "sysconf"))]
    #[futures_test::test]
    async fn test_udp_lookup_txt() {
        init();

        let inner = {
            let lookup = DnsLookup::over_udp().await.unwrap();

            let group = lookup
                .lookup_txt("_dnsaddr.am6.bootstrap.libp2p.io")
                .await
                .unwrap();

            log::trace!("{:?}", group);

            lookup.to_network()
        };

        sleep(Duration::from_secs(1)).await;

        assert_eq!(Arc::strong_count(&inner.0), 1);
    }

    #[ignore]
    #[cfg(all(feature = "mdns", feature = "rasi"))]
    #[futures_test::test]
    async fn test_mdns() {
        use futures::TryStreamExt;

        use crate::mdns::MdnsDiscover;

        init();

        let mut incoming = MdnsDiscover::all("_p2p._udp.local", Duration::from_secs(4))
            .await
            .unwrap()
            .into_incoming();

        while let Some((_, from)) = incoming.try_next().await.unwrap() {
            log::trace!("_p2p._udp.local from {:?}", from);
        }
    }
}
