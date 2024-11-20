//! A wrapper error type and a matching Result type
use std::ffi::{FromVecWithNulError, NulError};
use std::{error, fmt, io, num};

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    #[cfg(feature = "http")]
    HttpError(ureq::Error),
    IO(io::Error),
    Linux(nix::errno::Errno),
    NotImplemented(String),
    Nul(NulError),
    ParseInt(num::ParseIntError),
    FromVecWithNul(FromVecWithNulError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            #[cfg(feature = "http")]
            Error::HttpError(ref err) => write!(f, "{err:?}"),
            Error::IO(ref err) => write!(f, "{err:?}"),
            Error::Linux(err) => write!(f, "{:?}: {}", err, err.desc()),
            Error::NotImplemented(ref string) => write!(f, "not implemented: {string}"),
            Error::Nul(ref err) => write!(f, "{err}"),
            Error::ParseInt(ref err) => write!(f, "{err}"),
            Error::FromVecWithNul(ref err) => write!(f, "{err}"),
        }
    }
}

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match *self {
            #[cfg(feature = "http")]
            Error::HttpError(ref err) => Some(err),
            Error::IO(ref err) => Some(err),
            Error::Linux(ref err) => Some(err),
            Error::NotImplemented(_) => None,
            Error::Nul(ref err) => Some(err),
            Error::ParseInt(ref err) => Some(err),
            Error::FromVecWithNul(ref err) => Some(err),
        }
    }
}

#[cfg(feature = "http")]
impl From<ureq::Error> for Error {
    fn from(err: ureq::Error) -> Self {
        Error::HttpError(err)
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Error::IO(err)
    }
}

impl From<nix::errno::Errno> for Error {
    fn from(err: nix::errno::Errno) -> Self {
        Error::Linux(err)
    }
}

impl From<NulError> for Error {
    fn from(err: NulError) -> Self {
        Error::Nul(err)
    }
}

impl From<num::ParseIntError> for Error {
    fn from(err: num::ParseIntError) -> Self {
        Error::ParseInt(err)
    }
}

impl From<FromVecWithNulError> for Error {
    fn from(err: FromVecWithNulError) -> Self {
        Error::FromVecWithNul(err)
    }
}
