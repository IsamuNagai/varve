//! Varve consensus rules. No I/O; deterministic given its inputs.
//! The normative source is protocol/*.md; every rule here cites its section.

pub mod bignum;
pub mod block;
pub mod encoding;
pub mod genesis;
pub mod json;
pub mod networks;
mod networks_testnet;
pub mod params;
pub mod pow;
pub mod tx;
pub mod validate;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// encoding.md §1.5 parse error
    Parse(&'static str),
    /// validity failure
    Invalid(&'static str),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Error::Parse(s) => write!(f, "parse error: {}", s),
            Error::Invalid(s) => write!(f, "invalid: {}", s),
        }
    }
}

impl std::error::Error for Error {}
