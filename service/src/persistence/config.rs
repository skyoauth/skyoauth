//! Validated database configuration.

use std::{fmt, ops::RangeInclusive, str::FromStr, time::Duration};

use sqlx::postgres::PgConnectOptions;

/// Environment variable holding the PostgreSQL connection URL.
pub const DATABASE_URL_VAR: &str = "SKYOAUTH_DATABASE_URL";
/// Environment variable holding the maximum pool size (default 10).
pub const MAX_CONNECTIONS_VAR: &str = "SKYOAUTH_DATABASE_MAX_CONNECTIONS";
/// Environment variable holding the connection acquire timeout in seconds
/// (default 10).
pub const ACQUIRE_TIMEOUT_VAR: &str = "SKYOAUTH_DATABASE_ACQUIRE_TIMEOUT_SECS";

const MAX_CONNECTIONS: RangeInclusive<u32> = 1..=100;
const ACQUIRE_TIMEOUT_SECS: RangeInclusive<u32> = 1..=300;

/// PostgreSQL connection settings with a bounded pool size and acquire
/// timeout.
///
/// TLS follows the URL's `sslmode` parameter, which defaults to sqlx's
/// `prefer` (TLS if the server offers it, otherwise plaintext). Requiring TLS
/// is a follow-up (docs/skyoauth-tasks.md, T10.1).
///
/// `Debug` prints host, port, database, username and the pool limits, never
/// the password or the URL. The parsed sqlx connect options are not exposed
/// outside the `persistence` module, because their `Debug` includes the
/// password.
#[derive(Clone)]
pub struct DatabaseConfig {
    connect: PgConnectOptions,
    max_connections: u32,
    acquire_timeout: Duration,
}

/// A configuration error. Messages never include the connection URL, since
/// it may carry a password.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    /// A required variable is unset or empty.
    Missing(&'static str),
    /// The connection URL is not a valid `postgres://` or `postgresql://` URL.
    InvalidUrl,
    /// A numeric setting is not an integer within its bounds.
    OutOfRange {
        var: &'static str,
        bounds: RangeInclusive<u32>,
    },
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing(var) => write!(f, "{var} is not set"),
            Self::InvalidUrl => write!(
                f,
                "{DATABASE_URL_VAR} is not a valid postgres:// or postgresql:// URL"
            ),
            Self::OutOfRange { var, bounds } => write!(
                f,
                "{var} must be an integer from {} to {}",
                bounds.start(),
                bounds.end()
            ),
        }
    }
}

impl std::error::Error for ConfigError {}

impl DatabaseConfig {
    /// Builds a configuration from parsed connect options, enforcing the
    /// same bounds as [`DatabaseConfig::from_env`].
    pub fn new(
        connect: PgConnectOptions,
        max_connections: u32,
        acquire_timeout: Duration,
    ) -> Result<Self, ConfigError> {
        if !MAX_CONNECTIONS.contains(&max_connections) {
            return Err(out_of_range(MAX_CONNECTIONS_VAR, MAX_CONNECTIONS));
        }
        let (min, max) = ACQUIRE_TIMEOUT_SECS.into_inner();
        if !(Duration::from_secs(min.into())..=Duration::from_secs(max.into()))
            .contains(&acquire_timeout)
        {
            return Err(out_of_range(ACQUIRE_TIMEOUT_VAR, ACQUIRE_TIMEOUT_SECS));
        }
        Ok(Self {
            connect: connect.application_name("skyoauth-service"),
            max_connections,
            acquire_timeout,
        })
    }

    /// Reads the configuration from the process environment.
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_lookup(|var| std::env::var(var).ok())
    }

    /// Reads the configuration through `lookup`, which maps a variable name
    /// to its value. Unset or empty numeric settings take their defaults.
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Result<Self, ConfigError> {
        let get = |var| lookup(var).filter(|value| !value.is_empty());
        let url = get(DATABASE_URL_VAR).ok_or(ConfigError::Missing(DATABASE_URL_VAR))?;
        let scheme = url.split_once("://").map(|(scheme, _)| scheme);
        if !matches!(scheme, Some("postgres" | "postgresql")) {
            return Err(ConfigError::InvalidUrl);
        }
        // The parse error is dropped: its message may echo part of the URL.
        // TODO(tls): the follow-up appended to T10.1 in docs/skyoauth-tasks.md
        // defaults sslmode to verify-full for remote hosts; until then the URL
        // (or sqlx's `prefer`) decides.
        let connect = PgConnectOptions::from_str(&url).map_err(|_| ConfigError::InvalidUrl)?;
        let number = |var, default: u32, bounds| match get(var) {
            None => Ok(default),
            Some(value) => value.parse().map_err(|_| out_of_range(var, bounds)),
        };
        let max_connections = number(MAX_CONNECTIONS_VAR, 10, MAX_CONNECTIONS)?;
        let acquire_timeout = number(ACQUIRE_TIMEOUT_VAR, 10, ACQUIRE_TIMEOUT_SECS)?;
        Self::new(
            connect,
            max_connections,
            Duration::from_secs(acquire_timeout.into()),
        )
    }

    /// The parsed connect options. Not public: their `Debug` prints the
    /// password.
    pub(super) fn connect_options(&self) -> &PgConnectOptions {
        &self.connect
    }

    /// The maximum number of pooled connections.
    pub fn max_connections(&self) -> u32 {
        self.max_connections
    }

    /// How long to wait for a pooled connection, including establishing one.
    pub fn acquire_timeout(&self) -> Duration {
        self.acquire_timeout
    }
}

impl fmt::Debug for DatabaseConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DatabaseConfig")
            .field("host", &self.connect.get_host())
            .field("port", &self.connect.get_port())
            .field("database", &self.connect.get_database())
            .field("username", &self.connect.get_username())
            .field("max_connections", &self.max_connections)
            .field("acquire_timeout", &self.acquire_timeout)
            .finish_non_exhaustive()
    }
}

fn out_of_range(var: &'static str, bounds: RangeInclusive<u32>) -> ConfigError {
    ConfigError::OutOfRange { var, bounds }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "s3cr3t-pw";

    fn config(vars: &[(&str, &str)]) -> Result<DatabaseConfig, ConfigError> {
        DatabaseConfig::from_lookup(|var| {
            vars.iter()
                .find(|(k, _)| *k == var)
                .map(|(_, v)| v.to_string())
        })
    }

    #[test]
    fn defaults_apply_to_unset_and_empty_settings() {
        let url = format!("postgres://skyoauth:{SECRET}@db.example:5433/skyoauth");
        let config = config(&[(DATABASE_URL_VAR, &url), (MAX_CONNECTIONS_VAR, "")]).unwrap();
        assert_eq!(config.max_connections(), 10);
        assert_eq!(config.acquire_timeout(), Duration::from_secs(10));
        let connect = config.connect_options();
        assert_eq!(connect.get_host(), "db.example");
        assert_eq!(connect.get_port(), 5433);
        assert_eq!(connect.get_database(), Some("skyoauth"));
        assert_eq!(connect.get_application_name(), Some("skyoauth-service"));
    }

    #[test]
    fn explicit_settings_within_bounds_are_used() {
        let config = config(&[
            (DATABASE_URL_VAR, "postgresql://localhost/skyoauth"),
            (MAX_CONNECTIONS_VAR, "100"),
            (ACQUIRE_TIMEOUT_VAR, "1"),
        ])
        .unwrap();
        assert_eq!(config.max_connections(), 100);
        assert_eq!(config.acquire_timeout(), Duration::from_secs(1));
    }

    #[test]
    fn missing_or_empty_url_is_rejected() {
        for vars in [&[][..], &[(DATABASE_URL_VAR, "")][..]] {
            let err = config(vars).unwrap_err();
            assert_eq!(err.to_string(), "SKYOAUTH_DATABASE_URL is not set");
        }
    }

    #[test]
    fn invalid_url_is_rejected_without_echoing_it() {
        for url in [
            format!("mysql://root:{SECRET}@localhost/db"),
            format!("postgres://root:{SECRET}@localhost:notaport/db"),
            SECRET.to_string(),
        ] {
            let err = config(&[(DATABASE_URL_VAR, &url)]).unwrap_err();
            assert_eq!(err, ConfigError::InvalidUrl, "{url}");
            assert!(!err.to_string().contains(SECRET));
        }
    }

    #[test]
    fn out_of_range_settings_are_rejected() {
        let url = (DATABASE_URL_VAR, "postgres://localhost/skyoauth");
        for (var, value) in [
            (MAX_CONNECTIONS_VAR, "0"),
            (MAX_CONNECTIONS_VAR, "101"),
            (MAX_CONNECTIONS_VAR, "ten"),
            (ACQUIRE_TIMEOUT_VAR, "0"),
            (ACQUIRE_TIMEOUT_VAR, "301"),
            (ACQUIRE_TIMEOUT_VAR, "-1"),
        ] {
            let err = config(&[url, (var, value)]).unwrap_err();
            assert!(
                matches!(&err, ConfigError::OutOfRange { var: v, .. } if *v == var),
                "{var}={value}: {err:?}"
            );
        }
        assert_eq!(
            config(&[url, (MAX_CONNECTIONS_VAR, "0")])
                .unwrap_err()
                .to_string(),
            "SKYOAUTH_DATABASE_MAX_CONNECTIONS must be an integer from 1 to 100"
        );
    }

    #[test]
    fn debug_redacts_password_from_url_and_query() {
        for url in [
            format!("postgres://skyoauth:{SECRET}@db.example/skyoauth"),
            format!("postgres://skyoauth@db.example/skyoauth?password={SECRET}"),
        ] {
            let debug = format!("{:?}", config(&[(DATABASE_URL_VAR, &url)]).unwrap());
            assert!(!debug.contains(SECRET), "{debug}");
            assert!(debug.contains("db.example"), "{debug}");
        }
    }
}
