use std::fmt;

/// A plugin error: a message that ends up in the plugin log and in the
/// handler result the host sees.
///
/// Like `anyhow::Error`, it converts from any `std::error::Error`, so `?`
/// works on serde, I/O and parse errors.
pub struct Error {
    message: String,
}

impl Error {
    pub fn msg(message: impl Into<String>) -> Self {
        Error { message: message.into() }
    }

    pub fn message(&self) -> &str {
        &self.message
    }

    /// Prefixes the message, as in `context: message`.
    pub fn context(self, context: impl fmt::Display) -> Self {
        Error { message: format!("{context}: {}", self.message) }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl<E: std::error::Error> From<E> for Error {
    fn from(err: E) -> Self {
        Error { message: err.to_string() }
    }
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Adds context to errors, like `anyhow::Context`.
pub trait Context<T> {
    fn context(self, context: impl fmt::Display) -> Result<T>;
    fn with_context<C: fmt::Display, F: FnOnce() -> C>(self, f: F) -> Result<T>;
}

impl<T, E: Into<Error>> Context<T> for std::result::Result<T, E> {
    fn context(self, context: impl fmt::Display) -> Result<T> {
        self.map_err(|err| err.into().context(context))
    }

    fn with_context<C: fmt::Display, F: FnOnce() -> C>(self, f: F) -> Result<T> {
        self.map_err(|err| err.into().context(f()))
    }
}

impl<T> Context<T> for Option<T> {
    fn context(self, context: impl fmt::Display) -> Result<T> {
        self.ok_or_else(|| Error::msg(context.to_string()))
    }

    fn with_context<C: fmt::Display, F: FnOnce() -> C>(self, f: F) -> Result<T> {
        self.ok_or_else(|| Error::msg(f().to_string()))
    }
}

/// Returns early with an error built from a format string.
#[macro_export]
macro_rules! bail {
    ($($arg:tt)*) => {
        return ::core::result::Result::Err($crate::Error::msg(::std::format!($($arg)*)))
    };
}

/// Returns early with an error when the condition is false.
#[macro_export]
macro_rules! ensure {
    ($cond:expr, $($arg:tt)*) => {
        if !$cond {
            $crate::bail!($($arg)*);
        }
    };
}

/// Builds an error from a format string.
#[macro_export]
macro_rules! err {
    ($($arg:tt)*) => {
        $crate::Error::msg(::std::format!($($arg)*))
    };
}
