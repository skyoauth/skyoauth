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
/// "Remote" is judged on the address sqlx will dial: a `hostaddr` (from the
/// URL or [`DatabaseConfig::new`]'s argument, else `PGHOSTADDR`) when one is
/// set, otherwise the host name. A loopback host name paired with a
/// non-loopback `hostaddr` is therefore remote. sqlx's `sslmode=allow` never
/// negotiates TLS (it connects in plaintext, like `disable`).
///
/// # URL encoding
///
/// [`DatabaseConfig::from_lookup`] rejects, before sqlx parses it, a URL with
/// an unencoded `@`, `/`, `?` or `#` in the user name or password, an
/// unencoded `@` or `/` in the database name, or an unencoded `@` anywhere
/// after the host. Such a URL splits in the wrong place, and sqlx would then
/// log part of the password as an unrecognized query parameter or keep it as
/// the database name (which `Debug` prints). Percent-encode these characters
/// (`@` as `%40`, `/` as `%2F`, `?` as `%3F`, `#` as `%23`).
///
/// sqlx still reads the other `PG*` variables (`PGHOST`, `PGPORT`, `PGUSER`,
/// `PGPASSWORD`, `PGDATABASE`, `PGSSLROOTCERT`, `PGSSLCERT`, `PGSSLKEY`,
/// `PGOPTIONS`, `PGAPPNAME`, `PGHOSTADDR`) for settings the URL does not
/// carry. Set what matters in the URL.
///
/// `Debug` prints host, `hostaddr`, port, database, username, the SSL mode
/// and the pool limits, never the password or the URL. The parsed sqlx
/// connect options are not exposed outside the `persistence` module, because
/// their `Debug` includes the password.
#[derive(Clone)]
pub struct DatabaseConfig {
    connect: PgConnectOptions,
    /// The address sqlx dials instead of resolving the host name. Kept here
    /// because [`PgConnectOptions`] has no getter for it.
    hostaddr: Option<IpAddr>,
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
    /// The connection URL has a reserved character that must be
    /// percent-encoded, such as an `@`, `/`, `?` or `#` in the password.
    UnencodedUrlCharacter,
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
            Self::UnencodedUrlCharacter => write!(
                f,
                "{DATABASE_URL_VAR} has a character that must be percent-encoded: \
                 '@', '/', '?' or '#' in the user name or password, '@' or '/' in \
                 the database name, or '@' in the query (for example '@' as %40 \
                 and '/' as %2F)"
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
    ///
    /// `hostaddr` is the address to dial instead of resolving the host name;
    /// when set, it is applied to `connect` and decides whether the target is
    /// remote. A `hostaddr` set on `connect` itself cannot be read back
    /// ([`PgConnectOptions`] has no getter), so pass it here instead. When
    /// `hostaddr` is `None`, `PGHOSTADDR` from the environment is used, as
    /// sqlx does.
    pub fn new(
        connect: PgConnectOptions,
        hostaddr: Option<IpAddr>,
        max_connections: u32,
        acquire_timeout: Duration,
    ) -> Result<Self, ConfigError> {
        Self::with_ambient_hostaddr(
            connect,
            hostaddr,
            env_hostaddr(),
            max_connections,
            acquire_timeout,
        )
    }

    /// [`DatabaseConfig::new`] with the `PGHOSTADDR` value passed in, so
    /// tests do not depend on the environment.
    fn with_ambient_hostaddr(
        connect: PgConnectOptions,
        hostaddr: Option<IpAddr>,
        ambient_hostaddr: Option<IpAddr>,
        max_connections: u32,
        acquire_timeout: Duration,
    ) -> Result<Self, ConfigError> {
        Self::build(
            connect,
            hostaddr.or(ambient_hostaddr),
            max_connections,
            acquire_timeout,
        )
    }

    /// `hostaddr` is the address that will be dialed, if any; it is applied
    /// to `connect` so that the two cannot disagree.
    fn build(
        connect: PgConnectOptions,
        hostaddr: Option<IpAddr>,
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
        let connect = match hostaddr {
            Some(address) => connect.hostaddr(address),
            None => connect,
        };
        if is_weaker_than_verify_full_for_remote(&connect, hostaddr) {
            tracing::warn!(
                host = connect.get_host(),
                hostaddr = hostaddr.map(tracing::field::display),
                ssl_mode = ?connect.get_ssl_mode(),
                "database TLS is weaker than verify-full for a remote host"
            );
        }
        Ok(Self {
            connect: connect.application_name("skyoauth-service"),
            hostaddr,
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
    ///
    /// `PGHOSTADDR` is read from the process environment, not through
    /// `lookup`, because that is where sqlx reads it.
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Result<Self, ConfigError> {
        Self::from_lookup_with_ambient_hostaddr(lookup, env_hostaddr())
    }

    /// [`DatabaseConfig::from_lookup`] with the `PGHOSTADDR` value passed in,
    /// so tests do not depend on the environment.
    fn from_lookup_with_ambient_hostaddr(
        lookup: impl Fn(&str) -> Option<String>,
        ambient_hostaddr: Option<IpAddr>,
    ) -> Result<Self, ConfigError> {
        let get = |var| lookup(var).filter(|value| !value.is_empty());
        let url = get(DATABASE_URL_VAR).ok_or(ConfigError::Missing(DATABASE_URL_VAR))?;
        let scheme = url.split_once("://").map(|(scheme, _)| scheme);
        if !matches!(scheme, Some("postgres" | "postgresql")) {
            return Err(ConfigError::InvalidUrl);
        }
        // Checked before sqlx sees the URL: sqlx logs unrecognized query
        // parameters while parsing.
        if has_unencoded_url_character(&url) {
            return Err(ConfigError::UnencodedUrlCharacter);
        }
        // The parse error is dropped: its message may echo part of the URL.
        let connect = PgConnectOptions::from_str(&url).map_err(|_| ConfigError::InvalidUrl)?;
        let pairs = query_pairs(&url).ok_or(ConfigError::InvalidUrl)?;
        let hostaddr = url_hostaddr(&pairs).or(ambient_hostaddr);
        let mode = effective_ssl_mode(
            url_sets_ssl_mode(&pairs),
            is_remote(&connect, hostaddr),
            connect.get_ssl_mode(),
        );
        let connect = connect.ssl_mode(mode);
        let number = |var, default: u32, bounds| match get(var) {
            None => Ok(default),
            Some(value) => value.parse().map_err(|_| out_of_range(var, bounds)),
        };
        let max_connections = number(MAX_CONNECTIONS_VAR, 10, MAX_CONNECTIONS)?;
        let acquire_timeout = number(ACQUIRE_TIMEOUT_VAR, 10, ACQUIRE_TIMEOUT_SECS)?;
        Self::build(
            connect,
            hostaddr,
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
            .field("hostaddr", &self.hostaddr)
            .field("port", &self.connect.get_port())
            .field("database", &self.connect.get_database())
            .field("username", &self.connect.get_username())
            .field("ssl_mode", &self.connect.get_ssl_mode())
            .field("max_connections", &self.max_connections)
            .field("acquire_timeout", &self.acquire_timeout)
            .finish_non_exhaustive()
    }
}

/// Whether the raw URL has a reserved character that was not
/// percent-encoded and moves a component boundary, which would let part of
/// the password land where sqlx logs it or `Debug` prints it:
///
/// - a second `@` in the authority: an `@` in the user name or password;
/// - an `@` after the authority (in the path, query or fragment): the
///   authority ended early at a `/`, `?` or `#` in the password, or the
///   database name or a query value has an `@`;
/// - a `/` in the path after the leading one: a `/` in the database name.
///
/// The authority ends at the first `/`, `?` or `#`, as in the URL parser.
/// This looks at the string as written, not at what a parser made of it,
/// because a parser accepts most of these URLs with a different meaning.
fn has_unencoded_url_character(url: &str) -> bool {
    let Some((_, rest)) = url.split_once("://") else {
        return false;
    };
    let (authority, tail) = rest.split_at(rest.find(['/', '?', '#']).unwrap_or(rest.len()));
    let path = tail.split(['?', '#']).next().unwrap_or_default();
    authority.matches('@').count() > 1
        || tail.contains('@')
        || path.get(1..).is_some_and(|name| name.contains('/'))
}

/// The URL's decoded query pairs, which is how sqlx reads them (so an
/// encoded key such as `ssl%6Dode` means the same to both). `None` if the URL
/// does not parse.
fn query_pairs(url: &str) -> Option<Vec<(String, String)>> {
    let url = url::Url::parse(url).ok()?;
    Some(
        url.query_pairs()
            .map(|(key, value)| (key.into_owned(), value.into_owned()))
            .collect(),
    )
}

/// Whether the URL itself sets the SSL mode (`sslmode` or sqlx's `ssl-mode`
/// alias), as opposed to the mode coming from `PGSSLMODE` or a default.
fn url_sets_ssl_mode(pairs: &[(String, String)]) -> bool {
    pairs
        .iter()
        .any(|(key, _)| matches!(key.as_str(), "sslmode" | "ssl-mode"))
}

/// The `hostaddr` set in the URL, if any. sqlx applies the last one and
/// rejects a value that is not an IP address, so a value that does not parse
/// here cannot reach a connection.
fn url_hostaddr(pairs: &[(String, String)]) -> Option<IpAddr> {
    pairs
        .iter()
        .rev()
        .find(|(key, _)| key == "hostaddr")
        .and_then(|(_, value)| value.parse().ok())
}

/// The ambient `PGHOSTADDR`, read the way sqlx reads it (an unparsable value
/// is ignored).
fn env_hostaddr() -> Option<IpAddr> {
    std::env::var("PGHOSTADDR").ok()?.parse().ok()
}

/// Whether the connection leaves the machine: false for a Unix socket and
/// for a loopback target, true for every other host name or address. The
/// target is the `hostaddr` when one is set, because sqlx dials that address
/// in preference to the host name, and the host name otherwise.
fn is_remote(connect: &PgConnectOptions, hostaddr: Option<IpAddr>) -> bool {
    if connect.get_socket().is_some() || connect.get_host().starts_with('/') {
        return false;
    }
    if let Some(address) = hostaddr {
        return !address.is_loopback();
    }
    let host = connect
        .get_host()
        .trim_start_matches('[')
        .trim_end_matches(']');
    if host.eq_ignore_ascii_case("localhost") {
        return false;
    }
    !host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

/// Whether the connection leaves the machine with a mode weaker than
/// `verify-full`, which is what [`DatabaseConfig::new`] logs a WARN for.
fn is_weaker_than_verify_full_for_remote(
    connect: &PgConnectOptions,
    hostaddr: Option<IpAddr>,
) -> bool {
    is_remote(connect, hostaddr) && !matches!(connect.get_ssl_mode(), PgSslMode::VerifyFull)
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

    /// Reads a configuration from `vars` alone: `PGHOSTADDR` is taken as
    /// unset whatever the environment says. (sqlx itself still reads the
    /// `PG*` variables; every URL here sets what the assertions depend on.)
    fn config(vars: &[(&str, &str)]) -> Result<DatabaseConfig, ConfigError> {
        config_with_ambient_hostaddr(vars, None)
    }

    fn config_with_ambient_hostaddr(
        vars: &[(&str, &str)],
        ambient_hostaddr: Option<IpAddr>,
    ) -> Result<DatabaseConfig, ConfigError> {
        DatabaseConfig::from_lookup_with_ambient_hostaddr(
            |var| {
                vars.iter()
                    .find(|(k, _)| *k == var)
                    .map(|(_, v)| v.to_string())
            },
            ambient_hostaddr,
        )
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

    fn sets(url: &str) -> bool {
        url_sets_ssl_mode(&query_pairs(url).unwrap())
    }

    #[test]
    fn only_the_url_query_counts_as_setting_the_mode() {
        assert!(sets("postgres://h/db?sslmode=require"));
        assert!(sets("postgres://h/db?a=b&ssl-mode=require#x"));
        assert!(sets("postgres://h/db?ssl%6Dode=require"));
        assert!(sets("postgres://h/db?%73slmode=require"));
        assert!(!sets("postgres://h/db"));
        assert!(!sets("postgres://h/db?sslrootcert=/ca.pem"));
        assert!(!sets("postgres://u:sslmode=x@h/db"));
        assert!(!sets("postgres://h/db#sslmode=require"));
        assert!(!sets("postgres://h/db?xsslmode=require"));
    }

    #[test]
    fn an_encoded_ssl_mode_key_is_an_explicit_mode() {
        // sqlx decodes the key, so the URL asks for verify-full; the default
        // for a loopback host (prefer) must not replace it.
        let mode = ssl_mode("postgres://u@localhost/skyoauth?ssl%6Dode=verify-full");
        assert!(matches!(mode, PgSslMode::VerifyFull), "{mode:?}");
        let mode = ssl_mode("postgres://u@db.example/skyoauth?ssl%2Dmode=disable");
        assert!(matches!(mode, PgSslMode::Disable), "{mode:?}");
    }

    #[test]
    fn the_hostaddr_decides_what_counts_as_remote() {
        // sqlx dials `hostaddr` in preference to the host name.
        for (url, expected) in [
            ("postgres://u@localhost/db?hostaddr=10.0.0.5", "VerifyFull"),
            (
                "postgres://u@localhost/db?hostaddr=%31%30.0.0.5",
                "VerifyFull",
            ),
            (
                "postgres://u@127.0.0.1/db?hostaddr=2001:db8::1",
                "VerifyFull",
            ),
            ("postgres://u@db.example/db?hostaddr=127.0.0.1", "Prefer"),
            ("postgres://u@db.example/db?hostaddr=::1", "Prefer"),
            ("postgres://u@db.example/db?hostaddr=10.0.0.5", "VerifyFull"),
            // The last `hostaddr` wins, as in sqlx.
            (
                "postgres://u@db.example/db?hostaddr=10.0.0.5&hostaddr=127.0.0.1",
                "Prefer",
            ),
        ] {
            let mode = ssl_mode(url);
            assert_eq!(format!("{mode:?}"), expected, "{url}");
        }
    }

    #[test]
    fn a_loopback_name_with_a_remote_hostaddr_is_flagged_when_weak() {
        assert!(warns(
            "postgres://u@localhost/db?hostaddr=10.0.0.5&sslmode=prefer"
        ));
        assert!(!warns(
            "postgres://u@db.example/db?hostaddr=127.0.0.1&sslmode=prefer"
        ));
        assert!(!warns("postgres://u@localhost/db?hostaddr=10.0.0.5"));
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

    // The WARN itself is checked on the built binary in
    // `service/tests/tls_entry.rs`. A unit test cannot capture it reliably:
    // tracing caches each callsite's interest process-wide, so a scoped
    // subscriber races with other tests running in parallel threads.
    fn warns(url: &str) -> bool {
        flagged(&config(&[(DATABASE_URL_VAR, url)]).unwrap())
    }

    fn flagged(config: &DatabaseConfig) -> bool {
        is_weaker_than_verify_full_for_remote(config.connect_options(), config.hostaddr)
    }

    #[test]
    fn a_weak_explicit_mode_for_a_remote_host_is_flagged_for_a_warning() {
        for mode in ["disable", "allow", "prefer", "require", "verify-ca"] {
            let url = format!("postgres://u:{SECRET}@db.example/skyoauth?sslmode={mode}");
            assert!(warns(&url), "{mode}");
        }
    }

    #[test]
    fn strict_or_local_configurations_are_not_flagged() {
        for url in [
            "postgres://u@db.example/skyoauth",
            "postgres://u@db.example/skyoauth?sslmode=verify-full",
            "postgres://u@localhost/skyoauth?sslmode=disable",
            "postgres://u@localhost/skyoauth",
            "postgres:///skyoauth?host=/var/run/postgresql&sslmode=disable",
        ] {
            assert!(!warns(url), "{url}");
        }
    }

    #[test]
    fn debug_shows_the_ssl_mode() {
        let remote = config(&[(DATABASE_URL_VAR, "postgres://u@db.example/skyoauth")]).unwrap();
        assert!(format!("{remote:?}").contains("ssl_mode: VerifyFull"));
        let local = config(&[(DATABASE_URL_VAR, "postgres://u@localhost/skyoauth")]).unwrap();
        assert!(format!("{local:?}").contains("ssl_mode: Prefer"));
    }

    #[test]
    fn unencoded_reserved_characters_that_move_a_boundary_are_detected() {
        for url in [
            // `?`, `/` or `#` in the password ends the authority early.
            "postgres://u:40417?tail@db.example/db",
            "postgres://u:40417/tail@db.example/db",
            "postgres://u:/tail@db.example/db",
            "postgres://u:40417#tail@db.example/db",
            "postgres://u:a?b/c#d@db.example:5432/db?sslmode=require",
            // `@` in the user name or password.
            "postgres://u:p@ss@db.example/db",
            "postgres://admin@server:pw@db.example/db",
            // `@` or `/` in the database name, `@` in the query or fragment.
            "postgres://u@db.example/d@b",
            "postgres://u@db.example/a/b",
            "postgres://u@db.example//db",
            "postgres://u@db.example/db?user=admin@server",
            "postgres://u@db.example/db#a@b",
            "postgres://db.example?x@y",
        ] {
            assert!(has_unencoded_url_character(url), "{url}");
        }
    }

    #[test]
    fn encoded_or_well_placed_reserved_characters_are_accepted() {
        for url in [
            "postgres://u:40417%3Ftail@db.example/db",
            "postgres://u:40417%2Ftail%23x@db.example/db",
            "postgres://u:p%40ss@db.example/db",
            "postgres://admin%40server:pw@db.example/db",
            "postgres://u@db.example/a%2Fb",
            "postgres://u:pw@db.example",
            "postgres://u:pw@db.example/",
            "postgres://u:pw@[::1]:5432/db",
            "postgres://db.example/db",
            "postgres:///db?host=/var/run/postgresql",
            "postgres://u@db.example/db?sslrootcert=/etc/ssl/ca.pem&sslmode=verify-full",
            "postgres://u@db.example/db?password=a/b?c",
            "postgres://u@db.example/db?user=admin%40server",
        ] {
            assert!(!has_unencoded_url_character(url), "{url}");
        }
    }

    #[test]
    fn a_url_with_an_unencoded_password_character_is_rejected_without_echoing_it() {
        for separator in ["?", "/", "#", "@"] {
            let url = format!("postgres://u:40417{separator}{SECRET}@db.example/skyoauth");
            let err = config(&[(DATABASE_URL_VAR, &url)]).unwrap_err();
            assert_eq!(err, ConfigError::UnencodedUrlCharacter, "{url}");
            let message = err.to_string();
            assert!(message.contains("percent-encoded"), "{message}");
            for fragment in [SECRET, "40417", "db.example"] {
                assert!(!message.contains(fragment), "{message}");
            }
        }
        let encoded = format!("postgres://u:40417%3F{SECRET}@db.example/skyoauth");
        assert!(config(&[(DATABASE_URL_VAR, &encoded)]).is_ok());
    }

    const REMOTE: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 5));
    const LOOPBACK: IpAddr = IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);

    /// Connect options that depend on no ambient `PG*` setting the tests
    /// look at.
    fn options(host: &str) -> PgConnectOptions {
        PgConnectOptions::new_without_pgpass()
            .host(host)
            .ssl_mode(PgSslMode::Prefer)
    }

    fn new_config(
        host: &str,
        hostaddr: Option<IpAddr>,
        ambient_hostaddr: Option<IpAddr>,
    ) -> DatabaseConfig {
        DatabaseConfig::with_ambient_hostaddr(
            options(host),
            hostaddr,
            ambient_hostaddr,
            1,
            Duration::from_secs(1),
        )
        .unwrap()
    }

    #[test]
    fn a_hostaddr_given_to_new_is_dialed_and_decides_remote() {
        let config = new_config("localhost", Some(REMOTE), None);
        assert_eq!(config.hostaddr, Some(REMOTE));
        assert!(flagged(&config));
        assert!(format!("{config:?}").contains("hostaddr: Some(10.0.0.5)"));
        // Applied to the options, so the dialed address is the judged one.
        let options = format!("{:?}", config.connect_options());
        assert!(options.contains("hostaddr: Some(10.0.0.5)"), "{options}");

        let config = new_config("db.example", Some(LOOPBACK), None);
        assert!(!flagged(&config));
    }

    #[test]
    fn a_hostaddr_given_to_new_overrides_the_ambient_one() {
        let config = new_config("db.example", Some(LOOPBACK), Some(REMOTE));
        assert_eq!(config.hostaddr, Some(LOOPBACK));
        assert!(!flagged(&config));
        assert!(format!("{config:?}").contains("hostaddr: Some(127.0.0.1)"));

        let config = new_config("localhost", Some(REMOTE), Some(LOOPBACK));
        assert!(flagged(&config));
    }

    #[test]
    fn without_a_hostaddr_new_uses_the_ambient_one() {
        let config = new_config("localhost", None, Some(REMOTE));
        assert_eq!(config.hostaddr, Some(REMOTE));
        assert!(flagged(&config));

        let config = new_config("localhost", None, None);
        assert_eq!(config.hostaddr, None);
        assert!(!flagged(&config));
        assert!(format!("{config:?}").contains("hostaddr: None"));
    }

    #[test]
    fn the_url_hostaddr_overrides_the_ambient_one() {
        let ambient = |url: &str| {
            let config =
                config_with_ambient_hostaddr(&[(DATABASE_URL_VAR, url)], Some(REMOTE)).unwrap();
            (config.connect_options().get_ssl_mode(), config.hostaddr)
        };
        let (mode, hostaddr) = ambient("postgres://u@localhost/db");
        assert!(matches!(mode, PgSslMode::VerifyFull), "{mode:?}");
        assert_eq!(hostaddr, Some(REMOTE));
        let (mode, hostaddr) = ambient("postgres://u@localhost/db?hostaddr=127.0.0.1");
        assert!(matches!(mode, PgSslMode::Prefer), "{mode:?}");
        assert_eq!(hostaddr, Some(LOOPBACK));
    }
}
