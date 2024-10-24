use std::{error, fmt, io};

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    #[cfg(feature = "http")]
    HttpError(ureq::Error),
    IO(io::Error),
    LinuxError(nix::errno::Errno),
    NotImplemented(String),
}

impl fmt::Display for Error {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            #[cfg(feature = "http")]
            Error::HttpError(ref err) => write!(fmt, "{:?}", err),
            Error::IO(ref err) => write!(fmt, "{:?}", err),
            Error::LinuxError(err) => write!(fmt, "{:?}: {}", err, err.desc()),
            Error::NotImplemented(ref string) => write!(fmt, "not implemented: {}", string),
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
