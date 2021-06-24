use async_std::task::block_on;
use errors::Result;
use trojan::{ProxyBuilder, load_certs, load_keys};
use std::sync::Arc;
use rustls::{
    // AllowAnyAnonymousOrAuthenticatedClient, AllowAnyAuthenticatedClient,
    NoClientAuth,
    // RootCertStore,
    ServerConfig,
};
use std::io;
use async_tls::TlsAcceptor;




const PROXY: &str = "127.0.0.1:10443";
fn main() -> Result<()> {
    env_logger::init();


    let cert = "config.ssl.server().unwrap().cert.as_ref()".as_ref();
    let key = " config.ssl.server().unwrap().key.as_ref()".as_ref();
    let certs = load_certs(&cert)?;
    let key = load_keys(&key)?;
    let verifier =
    //     if let Some(auth) = auth {
    //     let roots = load_certs(&auth)?;
    //     let mut client_auth_roots = RootCertStore::empty();
    //     for root in roots {
    //         client_auth_roots.add(&root).unwrap();
    //     }
    //     if require_auth {
    //         AllowAnyAuthenticatedClient::new(client_auth_roots)
    //     } else {
    //         AllowAnyAnonymousOrAuthenticatedClient::new(client_auth_roots)
    //     }
    // } else {
    //     NoClientAuth::new()
    // };
        NoClientAuth::new();
    let mut tls_config = ServerConfig::new(verifier);
    tls_config
        .set_single_cert(certs, key)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;

    let tls_acceptor = TlsAcceptor::from(Arc::new(tls_config));


    block_on(async {

        let proxy = ProxyBuilder::new(PROXY.to_owned(), tls_acceptor);
        proxy.start().await.unwrap();
    });
    Ok(())
}
