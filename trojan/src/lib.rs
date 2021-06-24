pub mod authenticator;
mod copy;
mod proxy;

pub use fluvio_future::openssl::DefaultServerTlsStream;
pub use fluvio_future::openssl::TlsAcceptor;
pub use proxy::*;

use rustls::internal::pemfile::{certs, pkcs8_private_keys, rsa_private_keys};
use rustls::Certificate;
use rustls::PrivateKey;
use anyhow::anyhow;
use std::fs::File;
use std::io;
use std::io::BufReader;
use std::path::Path;
use errors::Error;
pub fn load_certs(path: &Path) -> Result<Vec<Certificate>, Error> {
    certs(&mut BufReader::new(File::open(path)?))
        .map_err(|_| Error::Eor(anyhow!("could not find carts")))
}

#[macro_export]
macro_rules! key {
    ($e:expr,$p:ident) => {
        let reader = &mut BufReader::new(File::open($p)?);
        if let Ok(mut keys) = $e(reader) {
            if !keys.is_empty() {
                return Ok(keys.remove(0));
            }
        }
    };
}
pub fn load_keys(path: &Path) -> io::Result<PrivateKey> {
    key!(pkcs8_private_keys, path);
    key!(rsa_private_keys, path);
    Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid key"))
}