//! The error type of the crate.

use std::fmt;

use crate::Category;

/// Everything that can go wrong in `anonyma-core`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// A category name that anonyma does not define.
    UnknownCategory(String),
    /// A preset name that anonyma does not define.
    UnknownPreset(String),
    /// A validator name that this crate does not provide.
    UnknownValidator(String),
    /// A strategy that this crate does not apply (yet), such as `encrypt`.
    UnsupportedStrategy(String),
    /// Categories this crate does not detect in full. An engine refuses them
    /// unless it is built with `allow_partial`: a privacy tool that silently
    /// skips a category it was asked to protect fails open.
    UnsupportedCategories(Vec<Category>),
    /// An argument that is out of its domain.
    Validation {
        /// The argument.
        field: String,
        /// What is wrong with it.
        message: String,
    },
    /// A token vault failed.
    Vault(String),
    /// A value outside the scope of an operation, such as a non-integer
    /// number in canonical JSON.
    Unsupported(String),
}

impl Error {
    pub(crate) fn validation(field: impl Into<String>, message: impl Into<String>) -> Self {
        Error::Validation {
            field: field.into(),
            message: message.into(),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::UnknownCategory(name) => write!(f, "unknown PII category \"{name}\""),
            Error::UnknownPreset(name) => write!(f, "unknown compliance preset \"{name}\""),
            Error::UnknownValidator(name) => write!(f, "unknown validator \"{name}\""),
            Error::UnsupportedStrategy(name) => {
                write!(
                    f,
                    "the \"{name}\" strategy is not available in anonyma-core yet"
                )
            }
            Error::UnsupportedCategories(categories) => {
                let names: Vec<&str> = categories.iter().map(|c| c.as_str()).collect();
                write!(
                    f,
                    "anonyma-core does not detect these categories in full yet: {}; \
                     allow partial detection explicitly, or use the TypeScript package \
                     or the sidecar",
                    names.join(", ")
                )
            }
            Error::Validation { field, message } => write!(f, "{field} {message}"),
            Error::Vault(message) => write!(f, "token vault: {message}"),
            Error::Unsupported(message) => write!(f, "unsupported: {message}"),
        }
    }
}

impl std::error::Error for Error {}

/// The result type of the crate.
pub type Result<T> = std::result::Result<T, Error>;
