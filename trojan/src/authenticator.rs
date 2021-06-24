use async_trait::async_trait;

use async_tls::server::TlsStream;
use async_std::net::TcpStream;


/// Abstracts logic to authenticate incoming stream and forward authoization context to target
#[async_trait]
pub trait Authenticator: Send + Sync {
    async fn authenticate(
        &self,
        incoming_tls_stream: &TlsStream<TcpStream>,
        target_tcp_stream: &TcpStream,
    ) -> Result<bool, std::io::Error>;
}

/// Null implementation where authenticate always returns true
pub(crate) struct NullAuthenticator;

#[async_trait]
impl Authenticator for NullAuthenticator {
    async fn authenticate(
        &self,
        _: &TlsStream<TcpStream>,
        _: &TcpStream,
    ) -> Result<bool, std::io::Error> {
        Ok(true)
    }
}
