//! The verified peer identity of an admin request (D5): a typed request
//! extension that only the rustls acceptor sets, never a header.

use std::fmt;

use axum::{extract::FromRequestParts, http::request::Parts};

use super::AdminHttpError;
use crate::identity::{IdentityError, canonical_public_identity};

/// The canonical public identity (`spki-sha256:<64 lowercase hex>`) of the
/// client certificate's key that the in-process rustls acceptor verified
/// (D5), carried as a request extension.
///
/// Nothing outside this crate can make one, and inside it only two
/// constructors exist: the acceptor's, which computes the identity from the
/// peer's DER `SubjectPublicKeyInfo` ([`canonical_public_identity`]), never
/// from a client-supplied string, and is visible only within
/// `crate::admin_http`, where the acceptor will live; and, under the
/// `test-support` feature only, the `#[doc(hidden)]`
/// `admin_http::test_support::with_admin_peer` of the integration tests'
/// fake acceptor. The field is private, and there is no `Default`,
/// `Deserialize`, `From` or `FromStr`, so neither the router, a handler, a
/// header nor a request body yields one.
///
/// As an extractor it reads only the extension: a request without one is
/// 401 `unauthenticated` ([`AdminHttpError::UNAUTHENTICATED`]), whatever its
/// headers say (`X-Client-Cert`, `X-Forwarded-Client-Cert` and the like are
/// never read). `Debug` leaves the identity out.
#[derive(Clone)]
pub struct AdminPeer {
    public_identity: String,
}

impl AdminPeer {
    /// The peer identity of a verified client certificate's
    /// `SubjectPublicKeyInfo` (DER): the acceptor's constructor.
    ///
    /// Refuses, as [`canonical_public_identity`] does, every key but an
    /// Ed25519 or ECDSA P-256 key in its one accepted `SubjectPublicKeyInfo`
    /// form ([`crate::identity`], "One form per accepted algorithm"), so a
    /// key has one peer identity.
    ///
    /// Not yet called: the rustls acceptor is a later slice (S6). Before it
    /// may call this, it must enforce the chain anchor's equality with the
    /// credential's `trust_anchor_ref` (D5).
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "the rustls acceptor (a later slice) is its caller"
        )
    )]
    pub(in crate::admin_http) fn from_peer_spki(spki_der: &[u8]) -> Result<Self, IdentityError> {
        Ok(Self {
            public_identity: canonical_public_identity(spki_der)?,
        })
    }

    /// The identity, compared byte-wise with
    /// `admin_credential.public_identity`.
    pub fn public_identity(&self) -> &str {
        &self.public_identity
    }
}

impl fmt::Debug for AdminPeer {
    /// Leaves out the identity.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AdminPeer").finish_non_exhaustive()
    }
}

impl<S: Send + Sync> FromRequestParts<S> for AdminPeer {
    type Rejection = AdminHttpError;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<Self>()
            .cloned()
            .ok_or(AdminHttpError::UNAUTHENTICATED)
    }
}

/// The integration tests' fake acceptor (`test-support` only).
#[cfg(feature = "test-support")]
#[doc(hidden)]
pub mod test_support {
    use axum::http::Request;

    use super::AdminPeer;

    /// `request` with the peer identity `public_identity` set as the
    /// acceptor sets it: the only constructor of an [`AdminPeer`] besides
    /// the acceptor's, for the tests' fake acceptor. The identity is taken
    /// as given (the registry's test operators have plain strings as their
    /// `public_identity`).
    pub fn with_admin_peer<B>(mut request: Request<B>, public_identity: &str) -> Request<B> {
        request.extensions_mut().insert(AdminPeer {
            public_identity: public_identity.to_owned(),
        });
        request
    }
}

#[cfg(test)]
mod tests {
    use axum::http::Request;

    use super::*;

    /// The DER `SubjectPublicKeyInfo` of an Ed25519 key and its identity,
    /// as in `service/tests/admin_workload.rs`.
    const ED25519_SPKI: [u8; 44] = [
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00, 0x51, 0xf4, 0x58,
        0x9a, 0x4c, 0xc7, 0x8f, 0xa1, 0xb0, 0xb8, 0xb6, 0x2c, 0x23, 0xeb, 0x53, 0x90, 0x68, 0x97,
        0x4c, 0x29, 0xee, 0x0c, 0x6a, 0x22, 0x94, 0x40, 0x51, 0x8d, 0x91, 0x63, 0xf0, 0xe4,
    ];
    const ED25519_IDENTITY: &str =
        "spki-sha256:280292eab9838fde657039d990410c3525af3bcf2882b2cbee438d905d6e877f";

    async fn extract(request: Request<()>) -> Result<AdminPeer, AdminHttpError> {
        let (mut parts, ()) = request.into_parts();
        AdminPeer::from_request_parts(&mut parts, &()).await
    }

    #[test]
    fn the_acceptors_constructor_computes_the_identity() {
        let peer = AdminPeer::from_peer_spki(&ED25519_SPKI).unwrap();
        assert_eq!(peer.public_identity(), ED25519_IDENTITY);
        assert!(matches!(
            AdminPeer::from_peer_spki(&[]),
            Err(IdentityError::Empty)
        ));
        assert!(matches!(
            AdminPeer::from_peer_spki(ED25519_IDENTITY.as_bytes()),
            Err(IdentityError::NotDer | IdentityError::NotSpki | IdentityError::Truncated)
        ));
        // The same key with NULL parameters: not the one Ed25519 form.
        let mut null_parameters = vec![
            0x30, 0x2c, 0x30, 0x07, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x05, 0x00,
        ];
        null_parameters.extend_from_slice(&ED25519_SPKI[9..]);
        assert!(matches!(
            AdminPeer::from_peer_spki(&null_parameters),
            Err(IdentityError::UnsupportedKey)
        ));
        assert_eq!(format!("{peer:?}"), "AdminPeer { .. }");
    }

    /// Only the extension yields a peer: every header that a proxy or a
    /// client might use to claim a certificate is ignored, also when it
    /// holds a real identity.
    #[tokio::test]
    async fn a_header_never_yields_a_peer() {
        let mut request = Request::builder();
        for name in [
            "x-client-cert",
            "x-ssl-client-cert",
            "x-forwarded-client-cert",
            "x-client-verify",
            "x-admin-peer",
            "ssl-client-cert",
            "authorization",
            "admin-peer",
        ] {
            request = request.header(name, ED25519_IDENTITY);
        }
        let err = extract(request.body(()).unwrap()).await.unwrap_err();
        assert_eq!(err, AdminHttpError::UNAUTHENTICATED);

        let mut request = Request::new(());
        // Another extension type with the same content is not a peer.
        request.extensions_mut().insert(ED25519_IDENTITY.to_owned());
        assert_eq!(
            extract(request).await.unwrap_err(),
            AdminHttpError::UNAUTHENTICATED
        );

        let mut request = Request::new(());
        request
            .extensions_mut()
            .insert(AdminPeer::from_peer_spki(&ED25519_SPKI).unwrap());
        let peer = extract(request).await.unwrap();
        assert_eq!(peer.public_identity(), ED25519_IDENTITY);
    }
}
