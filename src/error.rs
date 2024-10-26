//! A unified error type and a matching Result type
use std::ffi::{FromVecWithNulError, NulError};
use std::{error, fmt, io};

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    #[cfg(feature = "http")]
    HttpError(ureq::Error),
    IO(io::Error),
    LinuxError(nix::errno::Errno),
    NotImplemented(String),
    NulError(NulError),
    FromVecWithNulError(FromVecWithNulError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            #[cfg(feature = "http")]
            Error::HttpError(ref err) => write!(f, "{:?}", err),
            Error::IO(ref err) => write!(f, "{:?}", err),
            Error::LinuxError(err) => write!(f, "{:?}: {}", err, err.desc()),
            Error::NotImplemented(ref string) => write!(f, "not implemented: {}", string),
            Error::NulError(ref err) => write!(f, "{}", err),
            Error::FromVecWithNulError(ref err) => write!(f, "{}", err),
        }
    }
}

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match *self {
            #[cfg(feature = "http")]
            Error::HttpError(ref err) => Some(err),
            Error::IO(ref err) => Some(err),
            Error::LinuxError(ref err) => Some(err),
            Error::NotImplemented(_) => None,
            Error::NulError(ref err) => Some(err),
            Error::FromVecWithNulError(ref err) => Some(err),
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
        Error::LinuxError(err)
    }
}

impl From<NulError> for Error {
    fn from(err: NulError) -> Self {
        Error::NulError(err)
    }
}

impl From<FromVecWithNulError> for Error {
    fn from(err: FromVecWithNulError) -> Self {
        Error::FromVecWithNulError(err)
    }
}
