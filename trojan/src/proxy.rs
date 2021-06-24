use async_std::net::{TcpListener, TcpStream, UdpSocket};
use async_std::task::spawn;
use async_tls::server::TlsStream;
use async_tls::TlsAcceptor;
use bytes::{Buf, BufMut};
use errors::Error;
use errors::Result;
use futures_util::future::Either;
use futures_util::io::AsyncReadExt;
use futures_util::stream::StreamExt;
use futures_util::FutureExt;
use futures_util::{AsyncRead, AsyncWrite, AsyncWriteExt};
use log::debug;
use log::error;
use log::info;
use std::fmt::{Debug, Formatter};
use std::io::Cursor;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::{fmt, sync::Arc};
use x509_parser::nom::HexDisplay;
use crate::copy::copy;
pub struct ProxyBuilder {
    addr: String,
    acceptor: TlsAcceptor,
    authenticator: Vec<String>,
    fallback: String
}

impl ProxyBuilder {
    pub fn new(addr: String, acceptor: TlsAcceptor,authenticator: Vec<String>, fallback: String) -> Self {
        Self {
            addr,
            acceptor,
            authenticator,
            fallback
        }
    }

    pub async fn start(self) -> Result<()> {
        let listener = TcpListener::bind(&self.addr).await?;
        info!("proxy started at: {}", self.addr);
        let mut incoming = listener.incoming();
        let shared_authenticator = Arc::new(self.authenticator);

        while let Some(Ok(incoming_stream)) = incoming.next().await {
            debug!("server: got connection from client");
            let acceptor = self.acceptor.clone();
            spawn(process_stream(
                acceptor,
                incoming_stream,
                shared_authenticator.clone(),
                self.fallback.clone()
            ));
        }
        Ok(())
    }
}
/// start TLS stream at addr to target
async fn process_stream(
    acceptor: TlsAcceptor,
    raw_stream: TcpStream,
    authenticator: Arc<Vec<String>>,
    fallback: String
) {
    let source = raw_stream
        .peer_addr()
        .map(|addr| addr.to_string())
        .unwrap_or_else(|_| "".to_owned());

    debug!("new connection from {}", source);

    let handshake = acceptor.accept(raw_stream).await;

    match handshake {
        Ok(inner_stream) => {
            debug!("handshake success from: {}", source);
            if let Err(err) = proxy(inner_stream, source.clone(), authenticator,fallback).await {

                error!("error processing tls: {:?} from source: {}", err, source);

            }
        }
        Err(err) => error!("error handshaking: {:?} from source: {}", err, source),
    }
}
const HASH_STR_LEN: usize = 56;

/// ```plain
/// +-----------------------+---------+----------------+---------+----------+
/// | hex(SHA224(password)) |  CRLF   | Trojan Request |  CRLF   | Payload  |
/// +-----------------------+---------+----------------+---------+----------+
/// |          56           | X'0D0A' |    Variable    | X'0D0A' | Variable |
/// +-----------------------+---------+----------------+---------+----------+
///
/// where Trojan Request is a SOCKS5-like request:
///
/// +-----+------+----------+----------+
/// | CMD | ATYP | DST.ADDR | DST.PORT |
/// +-----+------+----------+----------+
/// |  1  |  1   | Variable |    2     |
/// +-----+------+----------+----------+
///
/// where:
///
/// o  CMD
/// o  CONNECT X'01'
/// o  UDP ASSOCIATE X'03'
/// o  ATYP address type of following address
/// o  IP V4 address: X'01'
/// o  DOMAINNAME: X'03'
/// o  IP V6 address: X'04'
/// o  DST.ADDR desired destination address
/// o  DST.PORT desired destination port in network octet order
/// ```
///
/// ```plain
/// +------+----------+----------+--------+---------+----------+
/// | ATYP | DST.ADDR | DST.PORT | Length |  CRLF   | Payload  |
/// +------+----------+----------+--------+---------+----------+
/// |  1   | Variable |    2     |   2    | X'0D0A' | Variable |
/// +------+----------+----------+--------+---------+----------+
/// ```
pub struct UdpAssociateHeader {
    pub addr: Address,
    pub payload_len: u16,
}

impl UdpAssociateHeader {
    #[inline]
    pub fn new(addr: &Address, payload_len: usize) -> Self {
        Self {
            addr: addr.clone(),
            payload_len: payload_len as u16,
        }
    }

    pub async fn read_from<R>(stream: &mut R) -> Result<Self>
    where
        R: AsyncRead + Unpin,
    {
        let addr = Address::read_from_stream(stream).await?;
        let mut buf = [0u8; 2];
        stream.read_exact(&mut buf).await?;
        let len = ((buf[0] as u16) << 8) | (buf[1] as u16);
        stream.read_exact(&mut buf).await?;
        Ok(Self {
            addr,
            payload_len: len,
        })
    }

    pub async fn write_to<W>(&self, w: &mut W) -> Result<()>
    where
        W: AsyncWrite + Unpin,
    {
        let mut buf = Vec::with_capacity(self.addr.serialized_len() + 2 + 1);
        let cursor = &mut buf;
        self.addr.write_to_buf(cursor);
        cursor.put_u16(self.payload_len);
        cursor.put_slice(b"\r\n");
        w.write_all(&buf).await?;
        Ok(())
    }
}
const CMD_TCP_CONNECT: u8 = 0x01;
const CMD_UDP_ASSOCIATE: u8 = 0x03;
async fn redirect_fallback( source: &str,target:  &str,   tls_stream: TlsStream<TcpStream>,buf: &[u8]) ->Result<()>{
    let mut tcp_stream = TcpStream::connect(target).await?;

    debug!("connect to fallback: {}", target);
    tcp_stream.write_all(buf).await?;

    let (mut target_stream, mut target_sink) = tcp_stream.split();
    let (mut from_tls_stream, mut from_tls_sink) = tls_stream.split();

    let s_t = format!("{}->{}", source.to_string(), target.to_string());
    let t_s = format!("{}->{}", target.to_string(), source.to_string());
    let source_to_target_ft = async move {
        match copy(&mut from_tls_stream, &mut target_sink, s_t.clone()).await {
            Ok(len) => {
                debug!("total {} bytes copied from source to target: {}", len, s_t);
            }
            Err(err) => {
                target_sink.close().await?;
                error!("{} error copying: {}", s_t, err);
            }
        }
        Ok::<(), Error>(())
    };

    let target_to_source_ft = async move {
        match copy(&mut target_stream, &mut from_tls_sink, t_s.clone()).await {
            Ok(len) => {
                debug!("total {} bytes copied from target: {}", len, t_s);
            }
            Err(err) => {
                from_tls_sink.close().await?;
                error!("{} error copying: {}", t_s, err);
            }
        }
        Ok::<(), Error>(())
    };
    futures::pin_mut!(source_to_target_ft);
    futures::pin_mut!(target_to_source_ft);
    // spawn(source_to_target_ft);
    // spawn(target_to_source_ft);
    let res = futures::future::select(source_to_target_ft, target_to_source_ft).await;
    match res {
        Either::Left((Err(e), _)) => {
            debug!("udp copy to remote closed");
            Err(anyhow::anyhow!(
                        "tcp proxy copy local to remote error: {:?}",
                        e
                    ))?
        }
        Either::Right((Err(e), _)) => {
            debug!("udp copy to local closed");
            Err(anyhow::anyhow!(
                        "tcp proxy copy remote to local error: {:?}",
                        e
                    ))?
        }
        Either::Left((Ok(_), _)) | Either::Right((Ok(_), _)) => (),
    };
    Ok(())
}
async fn proxy(
    mut tls_stream: TlsStream<TcpStream>,
    source: String,
    authenticator:  Arc<Vec<String>>,
    fallback: String
) -> Result<()> {

    let mut passwd_hash = [0u8; HASH_STR_LEN];
    let len = tls_stream.read(&mut passwd_hash).await?;
    if len != HASH_STR_LEN {
        // first_packet.extend_from_slice(&hash_buf[..len]);
        error!("first packet too short");
        redirect_fallback(&source,&fallback,tls_stream,&passwd_hash).await?;

        return Err(Error::Eor(anyhow::anyhow!("first packet too short")));
    }
    debug!("received client passwd: {:?}",String::from_utf8_lossy(&passwd_hash).to_string());
    if !authenticator.contains(& String::from_utf8_lossy(&passwd_hash).to_string()) {
        debug!("authentication failed, dropping connection");
        redirect_fallback(&source,&fallback,tls_stream,&passwd_hash).await?;
        return Err(Error::Eor(anyhow::anyhow!("authenticate failed")));
    } else {
        debug!("authentication succeeded");
    }
    let mut crlf_buf = [0u8; 2];
    let mut cmd_buf = [0u8; 1];

    tls_stream.read_exact(&mut crlf_buf).await?;
    tls_stream.read_exact(&mut cmd_buf).await?;
    let addr = Address::read_from_stream(&mut tls_stream).await?;
    tls_stream.read_exact(&mut crlf_buf).await?;

    match cmd_buf[0] {
        CMD_TCP_CONNECT => {
            debug!("TcpConnect target addr: {:?}", addr);

            let tcp_stream = TcpStream::connect(addr.to_string()).await?;



            debug!("connect to target: {} from source: {}", addr, source);

            let (mut target_stream, mut target_sink) = tcp_stream.split();
            let (mut from_tls_stream, mut from_tls_sink) = tls_stream.split();

            let s_t = format!("{}->{}", source, addr.to_string());
            let t_s = format!("{}->{}", addr.to_string(), source);
            let source_to_target_ft = async move {
                match copy(&mut from_tls_stream, &mut target_sink, s_t.clone()).await {
                    Ok(len) => {
                        debug!("total {} bytes copied from source to target: {}", len, s_t);
                    }
                    Err(err) => {
                        target_sink.close().await?;
                        error!("{} error copying: {}", s_t, err);
                    }
                }
                Ok::<(), Error>(())
            };

            let target_to_source_ft = async move {
                match copy(&mut target_stream, &mut from_tls_sink, t_s.clone()).await {
                    Ok(len) => {
                        debug!("total {} bytes copied from target: {}", len, t_s);
                    }
                    Err(err) => {
                        from_tls_sink.close().await?;
                        error!("{} error copying: {}", t_s, err);
                    }
                }
                Ok::<(), Error>(())
            };
            futures::pin_mut!(source_to_target_ft);
            futures::pin_mut!(target_to_source_ft);
            // spawn(source_to_target_ft);
            // spawn(target_to_source_ft);
            let res = futures::future::select(source_to_target_ft, target_to_source_ft).await;
            match res {
                Either::Left((Err(e), _)) => {
                    debug!("udp copy to remote closed");
                    Err(anyhow::anyhow!(
                        "tcp proxy copy local to remote error: {:?}",
                        e
                    ))?
                }
                Either::Right((Err(e), _)) => {
                    debug!("udp copy to local closed");
                    Err(anyhow::anyhow!(
                        "tcp proxy copy remote to local error: {:?}",
                        e
                    ))?
                }
                Either::Left((Ok(_), _)) | Either::Right((Ok(_), _)) => (),
            };
            // Ok(RequestHeader::TcpConnect(hash_buf, addr))
        }
        CMD_UDP_ASSOCIATE => {
            debug!("UdpAssociate target addr: {:?}", addr);

            const RELAY_BUFFER_SIZE: usize = 0x4000;
            let outbound = UdpSocket::bind(SocketAddr::from(SocketAddrV6::new(
                Ipv6Addr::UNSPECIFIED,
                0,
                0,
                0,
            )))
            .await?;
            let (mut tls_stream_reader, mut tls_stream_writer) = tls_stream.split();

            let client_to_server = Box::pin(async {
                loop {
                    let mut buf = [0u8; RELAY_BUFFER_SIZE];
                    let header = UdpAssociateHeader::read_from(&mut tls_stream_reader).await?;
                    if header.payload_len == 0{
                        break
                    }

                    tls_stream_reader
                        .read_exact(&mut buf[..header.payload_len as usize])
                        .await?;

                    match outbound
                        .send_to(&buf[..header.payload_len as usize], header.addr.to_string())
                        .await
                    {
                        Ok(n) => {
                            debug!("udp copy to remote: {} bytes", n);
                            // if n == 0 {
                            //     warn!();
                            // }
                        }
                        Err(e) => {
                            error!("udp send to upstream error: {:?}", e);
                            break;
                        }
                    }
                }
                Ok(()) as Result<()>
            })
            .fuse();
            let server_to_client = Box::pin(async {
                let mut buf = [0u8; RELAY_BUFFER_SIZE];
                loop {
                    let (len, dst) = outbound.recv_from(&mut buf).await?;
                    if len == 0 {
                        break;
                    }
                    let header = UdpAssociateHeader::new(&Address::from(dst), len);
                    header.write_to(&mut tls_stream_writer).await?;
                    tls_stream_writer.write_all(&buf[..len]).await?;
                    debug!("udp copy to client: {} bytes", len);
                }
                tls_stream_writer.flush().await?;
                tls_stream_writer.close().await?;
                Ok(()) as Result<()>
            })
            .fuse();
            let res = futures::future::select(client_to_server, server_to_client).await;
            match res {
                Either::Left((Err(e), _)) => {
                    debug!("udp copy to remote closed");
                    Err(anyhow::anyhow!(
                        "UdpAssociate copy local to remote error: {:?}",
                        e
                    ))?
                }
                Either::Right((Err(e), _)) => {
                    debug!("udp copy to local closed");
                    Err(anyhow::anyhow!(
                        "UdpAssociate copy remote to local error: {:?}",
                        e
                    ))?
                }
                Either::Left((Ok(_), _)) | Either::Right((Ok(_), _)) => (),
            };

            // Ok(RequestHeader::UdpAssociate(hash_buf))
        }
        _ => {
            error!("cant decode incoming stream");
            // Err(Error::Eor(anyhow::anyhow!("invalid command")))
        }
    };
    Ok(())
}
/// the following code copy from
/// https://github.com/p4gefau1t/trojan-r/blob/main/src/protocol/mod.rs
#[derive(Clone, PartialEq, Eq, Hash)]
pub enum Address {
    /// Socket address (IP Address)
    SocketAddress(SocketAddr),
    /// Domain name address
    DomainNameAddress(String, u16),
}
impl Address {
    const ADDR_TYPE_IPV4: u8 = 1;
    const ADDR_TYPE_DOMAIN_NAME: u8 = 3;
    const ADDR_TYPE_IPV6: u8 = 4;

    #[inline]
    fn serialized_len(&self) -> usize {
        match self {
            Address::SocketAddress(SocketAddr::V4(..)) => 1 + 4 + 2,
            Address::SocketAddress(SocketAddr::V6(..)) => 1 + 8 * 2 + 2,
            Address::DomainNameAddress(ref dmname, _) => 1 + 1 + dmname.len() + 2,
        }
    }

    async fn read_from_stream<R>(stream: &mut R) -> Result<Address>
    where
        R: AsyncRead + Unpin,
    {
        let mut addr_type_buf = [0u8; 1];
        let _ = stream.read_exact(&mut addr_type_buf).await?;

        let addr_type = addr_type_buf[0];
        match addr_type {
            Self::ADDR_TYPE_IPV4 => {
                let mut buf = [0u8; 6];
                stream.read_exact(&mut buf).await?;
                let mut cursor = Cursor::new(buf);

                let v4addr = Ipv4Addr::new(
                    cursor.get_u8(),
                    cursor.get_u8(),
                    cursor.get_u8(),
                    cursor.get_u8(),
                );
                let port = cursor.get_u16();
                Ok(Address::SocketAddress(SocketAddr::V4(SocketAddrV4::new(
                    v4addr, port,
                ))))
            }
            Self::ADDR_TYPE_IPV6 => {
                let mut buf = [0u8; 18];
                stream.read_exact(&mut buf).await?;

                let mut cursor = Cursor::new(&buf);
                let v6addr = Ipv6Addr::new(
                    cursor.get_u16(),
                    cursor.get_u16(),
                    cursor.get_u16(),
                    cursor.get_u16(),
                    cursor.get_u16(),
                    cursor.get_u16(),
                    cursor.get_u16(),
                    cursor.get_u16(),
                );
                let port = cursor.get_u16();

                Ok(Address::SocketAddress(SocketAddr::V6(SocketAddrV6::new(
                    v6addr, port, 0, 0,
                ))))
            }
            Self::ADDR_TYPE_DOMAIN_NAME => {
                let mut length_buf = [0u8; 1];
                let mut addr_buf = [0u8; 255 + 2];
                stream.read_exact(&mut length_buf).await?;
                let length = length_buf[0] as usize;

                // Len(Domain) + Len(Port)
                stream.read_exact(&mut addr_buf[..length + 2]).await?;

                let domain_buf = &addr_buf[..length];
                let addr = match String::from_utf8(domain_buf.to_vec()) {
                    Ok(addr) => addr,
                    Err(..) => return Err(Error::Eor(anyhow::anyhow!("invalid address encoding"))),
                };
                let mut port_buf = &addr_buf[length..length + 2];
                let port = port_buf.get_u16();

                Ok(Address::DomainNameAddress(addr, port))
            }
            _ => {
                // Wrong Address Type . Socks5 only supports ipv4, ipv6 and domain name
                Err(Error::Eor(anyhow::anyhow!(
                    "not supported address type {:#x}",
                    addr_type
                )))
            }
        }
    }
    fn write_to_buf<B: BufMut>(&self, buf: &mut B) {
        match self {
            Self::SocketAddress(SocketAddr::V4(addr)) => {
                buf.put_u8(Self::ADDR_TYPE_IPV4);
                buf.put_slice(&addr.ip().octets());
                buf.put_u16(addr.port());
            }
            Self::SocketAddress(SocketAddr::V6(addr)) => {
                buf.put_u8(Self::ADDR_TYPE_IPV6);
                for seg in &addr.ip().segments() {
                    buf.put_u16(*seg);
                }
                buf.put_u16(addr.port());
            }
            Self::DomainNameAddress(domain_name, port) => {
                buf.put_u8(Self::ADDR_TYPE_DOMAIN_NAME);
                buf.put_u8(domain_name.len() as u8);
                buf.put_slice(&domain_name.as_bytes()[..]);
                buf.put_u16(*port);
            }
        }
    }
}

impl Debug for Address {
    #[inline]
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match *self {
            Address::SocketAddress(ref addr) => write!(f, "{}", addr),
            Address::DomainNameAddress(ref addr, ref port) => write!(f, "{}:{}", addr, port),
        }
    }
}

impl fmt::Display for Address {
    #[inline]
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match *self {
            Address::SocketAddress(ref addr) => write!(f, "{}", addr),
            Address::DomainNameAddress(ref addr, ref port) => write!(f, "{}:{}", addr, port),
        }
    }
}
impl From<SocketAddr> for Address {
    fn from(s: SocketAddr) -> Address {
        Address::SocketAddress(s)
    }
}
