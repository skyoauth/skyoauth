//! Validated database configuration.

use std::{fmt, net::IpAddr, ops::RangeInclusive, str::FromStr, time::Duration};

use sqlx::postgres::{PgConnectOptions, PgSslMode};

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
/// # TLS
///
/// A URL that sets `sslmode` is used as written. Without `sslmode`, a remote
/// host gets `verify-full` and a loopback or Unix-socket host gets sqlx's
/// `prefer`. The ambient `PGSSLMODE` variable is ignored in both cases, so a
/// stray environment value cannot weaken the default. An explicit mode weaker
/// than `verify-full` for a remote host is accepted, with a WARN log. The
/// certificate is checked against the public (webpki) roots; a private CA
/// needs `sslrootcert=<path>` in the URL.
///
/// sqlx still reads the other `PG*` variables (`PGHOST`, `PGPORT`, `PGUSER`,
/// `PGPASSWORD`, `PGDATABASE`, `PGSSLROOTCERT`, `PGSSLCERT`, `PGSSLKEY`,
/// `PGOPTIONS`, `PGAPPNAME`, `PGHOSTADDR`) for settings the URL does not
/// carry. Set what matters in the URL.
///
/// `Debug` prints host, port, database, username, the SSL mode and the pool
/// limits, never the password or the URL. The parsed sqlx connect options are
/// not exposed outside the `persistence` module, because their `Debug`
/// includes the password.
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
        if is_remote(&connect) && !matches!(connect.get_ssl_mode(), PgSslMode::VerifyFull) {
            tracing::warn!(
                host = connect.get_host(),
                ssl_mode = ?connect.get_ssl_mode(),
                "database TLS is weaker than verify-full for a remote host"
            );
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
        let connect = PgConnectOptions::from_str(&url).map_err(|_| ConfigError::InvalidUrl)?;
        let mode = effective_ssl_mode(
            url_sets_ssl_mode(&url),
            is_remote(&connect),
            connect.get_ssl_mode(),
        );
        let connect = connect.ssl_mode(mode);
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
            .field("ssl_mode", &self.connect.get_ssl_mode())
            .field("max_connections", &self.max_connections)
            .field("acquire_timeout", &self.acquire_timeout)
            .finish_non_exhaustive()
    }
}

/// Whether the URL itself sets the SSL mode (`sslmode` or sqlx's `ssl-mode`
/// alias), as opposed to the mode coming from `PGSSLMODE` or a default.
fn url_sets_ssl_mode(url: &str) -> bool {
    let url = url.split_once('#').map_or(url, |(url, _)| url);
    url.split_once('?').is_some_and(|(_, query)| {
        query.split('&').any(|pair| {
            let key = pair.split_once('=').map_or(pair, |(key, _)| key);
            matches!(key, "sslmode" | "ssl-mode")
        })
    })
}

/// Whether the connection leaves the machine: false for a Unix socket and
/// for `localhost` or a loopback address, true for every other host name or
/// address.
fn is_remote(connect: &PgConnectOptions) -> bool {
    if connect.get_socket().is_some() {
        return false;
    }
    let host = connect.get_host();
    if host.starts_with('/') {
        return false;
    }
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if host.eq_ignore_ascii_case("localhost") {
        return false;
    }
    !host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

/// The SSL mode to use. An explicit URL value wins. Otherwise `parsed`, which
/// may come from `PGSSLMODE`, is ignored: remote hosts get `verify-full`,
/// local ones sqlx's default `prefer`.
fn effective_ssl_mode(explicit: bool, remote: bool, parsed: PgSslMode) -> PgSslMode {
    match (explicit, remote) {
        (true, _) => parsed,
        (false, true) => PgSslMode::VerifyFull,
        (false, false) => PgSslMode::Prefer,
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

    fn ssl_mode(url: &str) -> PgSslMode {
        config(&[(DATABASE_URL_VAR, url)])
            .unwrap()
            .connect_options()
            .get_ssl_mode()
    }

    #[test]
    fn remote_hosts_default_to_verify_full() {
        for host in [
            "db.example",
            "10.0.0.5",
            "[2001:db8::1]",
            "localhost.example",
        ] {
            let mode = ssl_mode(&format!("postgres://u@{host}/skyoauth"));
            assert!(matches!(mode, PgSslMode::VerifyFull), "{host}: {mode:?}");
        }
    }

    #[test]
    fn local_hosts_default_to_prefer() {
        for url in [
            "postgres://u@localhost/skyoauth",
            "postgres://u@LOCALHOST:5433/skyoauth",
            "postgres://u@127.0.0.1/skyoauth",
            "postgres://u@127.1.2.3/skyoauth",
            "postgres://u@[::1]/skyoauth",
            "postgres:///skyoauth?host=/var/run/postgresql",
        ] {
            let mode = ssl_mode(url);
            assert!(matches!(mode, PgSslMode::Prefer), "{url}: {mode:?}");
        }
    }

    #[test]
    fn an_explicit_mode_in_the_url_is_used_as_written() {
        for (query, expected) in [
            ("sslmode=disable", "Disable"),
            ("sslmode=require", "Require"),
            ("sslmode=verify-ca", "VerifyCa"),
            ("sslmode=verify-full", "VerifyFull"),
            ("ssl-mode=allow", "Allow"),
            ("application_name=x&sslmode=prefer", "Prefer"),
        ] {
            let mode = ssl_mode(&format!("postgres://u@db.example/skyoauth?{query}"));
            assert_eq!(format!("{mode:?}"), expected, "{query}");
        }
        let local = ssl_mode("postgres://u@localhost/skyoauth?sslmode=require");
        assert!(matches!(local, PgSslMode::Require));
    }

    #[test]
    fn only_the_url_query_counts_as_setting_the_mode() {
        assert!(url_sets_ssl_mode("postgres://h/db?sslmode=require"));
        assert!(url_sets_ssl_mode("postgres://h/db?a=b&ssl-mode=require#x"));
        assert!(!url_sets_ssl_mode("postgres://h/db"));
        assert!(!url_sets_ssl_mode("postgres://h/db?sslrootcert=/ca.pem"));
        assert!(!url_sets_ssl_mode("postgres://u:sslmode=x@h/db"));
        assert!(!url_sets_ssl_mode("postgres://h/db#sslmode=require"));
        assert!(!url_sets_ssl_mode("postgres://h/db?xsslmode=require"));
    }

    #[test]
    fn the_ambient_mode_never_overrides_the_default() {
        // `parsed` stands for whatever PGSSLMODE produced.
        for parsed in [
            PgSslMode::Disable,
            PgSslMode::Allow,
            PgSslMode::Prefer,
            PgSslMode::Require,
            PgSslMode::VerifyCa,
            PgSslMode::VerifyFull,
        ] {
            let remote = effective_ssl_mode(false, true, parsed);
            assert!(matches!(remote, PgSslMode::VerifyFull), "{parsed:?}");
            let local = effective_ssl_mode(false, false, parsed);
            assert!(matches!(local, PgSslMode::Prefer), "{parsed:?}");
            let explicit = effective_ssl_mode(true, true, parsed);
            assert_eq!(format!("{explicit:?}"), format!("{parsed:?}"));
        }
    }

    /// Runs `f` with WARN-and-above logs captured in memory.
    fn warnings(f: impl FnOnce()) -> String {
        #[derive(Clone, Default)]
        struct Sink(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
        impl std::io::Write for Sink {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Sink {
            type Writer = Self;
            fn make_writer(&'a self) -> Self {
                self.clone()
            }
        }
        let sink = Sink::default();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::WARN)
            .with_ansi(false)
            .with_writer(sink.clone())
            .finish();
        tracing::subscriber::with_default(subscriber, f);
        String::from_utf8(sink.0.lock().unwrap().clone()).unwrap()
    }

    #[test]
    fn a_weak_explicit_mode_for_a_remote_host_logs_a_warning() {
        for mode in ["disable", "allow", "prefer", "require", "verify-ca"] {
            let url = format!("postgres://u:{SECRET}@db.example/skyoauth?sslmode={mode}");
            let logs = warnings(|| {
                config(&[(DATABASE_URL_VAR, &url)]).unwrap();
            });
            assert!(logs.contains("WARN"), "{mode}: {logs}");
            assert!(logs.contains("db.example"), "{mode}: {logs}");
            assert!(!logs.contains(SECRET), "{mode}: {logs}");
        }
    }

    #[test]
    fn strict_or_local_configurations_log_no_warning() {
        for url in [
            "postgres://u@db.example/skyoauth",
            "postgres://u@db.example/skyoauth?sslmode=verify-full",
            "postgres://u@localhost/skyoauth?sslmode=disable",
            "postgres://u@localhost/skyoauth",
            "postgres:///skyoauth?host=/var/run/postgresql&sslmode=disable",
        ] {
            let logs = warnings(|| {
                config(&[(DATABASE_URL_VAR, url)]).unwrap();
            });
            assert!(logs.is_empty(), "{url}: {logs}");
        }
    }

    #[test]
    fn debug_shows_the_ssl_mode() {
        let remote = config(&[(DATABASE_URL_VAR, "postgres://u@db.example/skyoauth")]).unwrap();
        assert!(format!("{remote:?}").contains("ssl_mode: VerifyFull"));
        let local = config(&[(DATABASE_URL_VAR, "postgres://u@localhost/skyoauth")]).unwrap();
        assert!(format!("{local:?}").contains("ssl_mode: Prefer"));
    }
}
