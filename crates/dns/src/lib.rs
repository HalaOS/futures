#![cfg_attr(docsrs, feature(doc_cfg))]

#[cfg(feature = "nslookup")]
#[cfg_attr(docsrs, doc(cfg(feature = "nslookup")))]
pub mod nslookup;

#[cfg(feature = "mdns")]
#[cfg_attr(docsrs, doc(cfg(feature = "mdns")))]
pub mod mdns;

mod errors;
pub use errors::*;

#[cfg(feature = "rasi")]
#[cfg_attr(docsrs, doc(cfg(feature = "rasi")))]
pub mod rasi;

#[cfg(feature = "sysconf")]
#[cfg_attr(docsrs, doc(cfg(feature = "sysconf")))]
pub mod sysconf;

pub mod message;
