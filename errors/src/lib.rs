// #![feature(try_trait)]

use thiserror::Error;
// use trust_dns_resolver::errors::ResolveError;
use glommio::GlommioError;
use sqlx::sqlite::SqliteError;
use std::io;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    // #[errors("Already called shutdown")]
    // AlreadyShutdown,
    // #[errors("Found data that is too large to decode: {0}")]
    // DataTooLarge(usize),
    #[error("Network Error: {0:?}")]
    NetworkError(NetworkError),

    #[error("Service Error: {0:?}")]
    ServiceError(ServiceError),
    // #[errors("No active stream")]
    // NoActiveStream,
    // #[errors("Remote stream cleanly closed")]
    // RemoteStreamClosed,
    #[error("IO errors")]
    IoError(#[from] io::Error),

    #[error("IO errors")]
    TonicError(#[from] tonic::transport::Error),
    #[error("Resolver errors")]
    Resolver(#[from] trust_dns_resolver::error::ResolveError),

    #[error("IO errors")]
    GlommioError(#[from] GlommioError<()>),
    #[error("Sql errors")]
    SqlError(#[from] sqlx::Error),

    #[error("hyper errors")]
    HyperError(#[from] hyper::Error),
    #[error("hyper errors")]
    HyperBodyError(#[from] hyper::http::Error),

    #[error("future timeout")]
    TimeoutError(#[from] async_std::future::TimeoutError),
    #[error("Error: {0:?}")]
    Eor(#[from] anyhow::Error),
}
impl From<NetworkError> for Error {
    fn from(err: NetworkError) -> Error {
        Error::NetworkError(err)
    }
}

impl From<ServiceError> for Error {
    fn from(err: ServiceError) -> Error {
        Error::ServiceError(err)
    }
}
// #[errors(transparent)]
#[derive(Debug, Error)]
pub enum NetworkError {
    #[error("IO errors")]
    IoError(#[from] io::Error),
    #[error("Resolver errors")]
    ResolverError,
    #[error("Peer not connected")]
    NotConnected,
}

/// An error returned by a provider
#[derive(Debug, Error)]
pub enum ServiceError {
    /// The requested entity does not exist
    #[error("Entity does not exist")]
    NotFound,
    /// The operation violates a uniqueness constraint
    #[error("{0}")]
    UniqueViolation(String),
    /// The requested operation violates the data model
    #[error("{0}")]
    ModelViolation(String),
    #[error(transparent)]
    /// A generic unhandled error
    Provider(sqlx::Error),
    #[error("Invalid qequest parameters")]
    InvalidParams,

    #[error("Invalid token")]
    InvalidToken,

    #[error("does not have permission")]
    NoPermission,

    #[error("token can not access to the server")]
    LimitedToken,

    #[error("illegal access")]
    IllegalAccess,

    #[error("this token has already been occupied")]
    TokenOccupied,

    #[error("token is illegal")]
    IllegalToken,

    #[error("internal error occurred")]
    InternalError,

    #[error("Error setting timeout")]
    TimerError,

    // #[error("Provider error occurred")]
    // ProvideError(ProvideErrorKind),
    #[error("internal data provider occurred")]
    DataError,

    #[error("Sql internal error")]
    SqlError(#[from] SqliteError),
}
// impl From<std::option::NoneError> for ServiceError {
//     fn from(_: std::option::NoneError) -> ServiceError {
//         Self::NotFound
//         // anyhow::Error::new(inner)
//         //     .context(ProvideErrorKind::NotFound)
//         //     .into()
//     }
// }

// impl From<std::option::NoneError> for ProvideErrorKind {
//     fn from(inner: std::option::NoneError) -> ProvideErrorKind {
//         anyhow::Error::new(inner)
//             .context(ProvideErrorKind::NotFound)
//             .into()
//     }
// }

/*impl From<sqlx::Error> for ServiceError {
    /// Convert a SQLx error into a provider error
    ///
    /// For Database errors we attempt to downcast
    ///
    /// FIXME(RFC): I have no idea if this is sane
    fn from(e: sqlx::Error) -> Self {
        log::debug!("sqlx returned err -- {:#?}", &e);
        match e {
            sqlx::Error::RowNotFound => ServiceError::NotFound,
            sqlx::Error::Database(db_err) => {
                #[cfg(feature = "postgres")]
                {
                    if let Some(pg_err) = db_err.try_downcast_ref::<sqlx::postgres::PgError>() {
                        if let Ok(provide_err) = ProvideErrorKind::try_from(pg_err) {
                            return provide_err;
                        }
                    }
                }

                #[cfg(feature = "sqlite")]
                {
                    if let Some(sqlite_err) = db_err.try_downcast_ref::<sqlx::sqlite::SqliteError>()
                    {
                        let provide_err = ServiceError::from(sqlite_err);
                        return provide_err;

                    }
                }

                ServiceError::Provider(sqlx::Error::Database(db_err))
            }
            _ => ServiceError::Provider(e),
        }
    }
}
*/
