use async_std::task::block_on;
use errors::Result;
use trojan::{ProxyBuilder, TlsAcceptor};
const PROXY: &str = "127.0.0.1:10443";
fn main() -> Result<()> {
    env_logger::init();
    block_on(async {
        let acceptor = TlsAcceptor::builder().unwrap()
            .with_certifiate_and_key_from_pem_files(
                "certs/certs/server.crt",
                "certs/certs/server.key",
            ).unwrap()
            .build();
        let proxy = ProxyBuilder::new(PROXY.to_owned(), acceptor);
        proxy.start().await.unwrap();
    });
    Ok(())
}
