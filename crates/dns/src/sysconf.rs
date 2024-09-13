#[cfg(unix)]
mod unix {
    use std::net::{IpAddr, SocketAddr};

    use crate::{Error, Result};

    /// Get the system-wide DNS name server configuration.
    pub fn name_server() -> Result<SocketAddr> {
        let config = std::fs::read("/etc/resolv.conf")?;

        let config = resolv_conf::Config::parse(&config)?;

        for name_server in config.nameservers {
            let ip_addr: IpAddr = name_server.into();

            return Ok((ip_addr, 53).into());
        }

        return Err(Error::SysWideNameServer.into());
    }
}

#[cfg(unix)]
pub use unix::*;

#[cfg(windows)]
mod windows {
    use std::net::SocketAddr;

    use crate::{Error, Result};

    /// Get the system-wide DNS name server configuration.
    pub fn name_server() -> Result<SocketAddr> {
        for adapter in ipconfig::get_adapters()? {
            for ip_addr in adapter.dns_servers() {
                return Ok((ip_addr.clone(), 53).into());
            }
        }

        return Err(Error::SysWideNameServer.into());
    }
}

#[cfg(windows)]
pub use windows::*;
