mod copy;
mod proxy;

pub use fluvio_future::openssl::DefaultServerTlsStream;
pub use fluvio_future::openssl::TlsAcceptor;
pub use proxy::*;
use sha2::{Digest, Sha224};
use hex::encode;
use anyhow::anyhow;
use errors::{Error,Result};
use rustls::internal::pemfile::{certs, pkcs8_private_keys, rsa_private_keys};
use rustls::Certificate;
use rustls::PrivateKey;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;
pub fn load_certs(path: &Path) -> Result<Vec<Certificate>> {
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
pub fn load_keys(path: &Path) -> Result<PrivateKey> {
    key!(pkcs8_private_keys, path);
    key!(rsa_private_keys, path);
    Err(Error::Eor(anyhow::anyhow!("invalid key")))
}



pub fn generate_authenticator(passwd_list: &Vec<String>) -> Result<Vec<String>> {
    let mut authenticator = Vec::with_capacity(passwd_list.len());
    for passwd in passwd_list{
        let mut hasher = Sha224::new();
        hasher.update(passwd.as_bytes());
        let encode_passwd = encode(hasher.finalize());
        authenticator.push(encode_passwd);
    }
    Ok(authenticator)
}