use async_std::task::block_on;
use async_tls::TlsAcceptor;
use errors::Result;
use rustls::{
    // AllowAnyAnonymousOrAuthenticatedClient, AllowAnyAuthenticatedClient,
    NoClientAuth,
    // RootCertStore,
    ServerConfig,
};
use std::io;
use std::sync::Arc;
use trojan::{load_certs, load_keys, ProxyBuilder, generate_authenticator};
use async_std::task::spawn;
const PROXY: &str = "0.0.0.0:10443";
const FALLBACK: &str = "127.0.0.1:28080";
fn main() -> Result<()> {
     let passwd_lst = vec!["damo".to_string()];
    let authenticator= generate_authenticator(&passwd_lst)?;
    println!("authenticator: {:?}",authenticator);
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
    let test_fut = async{

        tide::log::start();
        let mut app = tide::new();
        app.at("/").get(|_| async { Ok("Hello, world!") });
        app.listen("127.0.0.1:28080").await?;
        Ok(()) as Result<()>
    };




    block_on(async {
        spawn(test_fut);
        let proxy = ProxyBuilder::new(PROXY.to_owned(), tls_acceptor, authenticator, FALLBACK.to_owned());
        proxy.start().await?;
        Ok(()) as Result<()>
    })?;
    Ok(())
}
