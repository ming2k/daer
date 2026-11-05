// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Duration;

use netune::{Preset, SocketConfig};

use crate::error::ProxyProtocolError;
use crate::fragment::Fragment;

/// Socket options and deadlines shared by every node dialer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DialerOptions {
    /// `SO_MARK`, applied before `connect(2)`.
    pub so_mark: Option<u32>,
    pub timeout: Duration,
    /// `[global.tls] profile`: a netune preset name, used by every outbound that rides netune's
    /// TLS stack (`trojan`, and any future TLS-based connector).
    ///
    /// Carried here rather than read per connector because the profile is a property of the
    /// *deployment*: one daemon presents one ClientHello identity, and two nodes of the same
    /// deployment disagreeing about it would be a fingerprint leak in its own right.
    ///
    /// `None` keeps netune's default identity. A name that is not a registered preset is a
    /// **load-time** error (`DialerOptions::with_tls_profile`), because a silently different
    /// ClientHello defeats the point of configuring one.
    pub tls_profile: Option<&'static str>,
    /// `[global.tls] fragment`: slice a handshake daer owns. Only a REALITY session qualifies,
    /// because a `trojan://` node's ClientHello is written by netune inside its own connector.
    pub fragment: Option<Fragment>,
}

impl DialerOptions {
    pub fn new(so_mark: Option<u32>, timeout: Duration) -> Self {
        Self {
            so_mark,
            timeout,
            tls_profile: None,
            fragment: None,
        }
    }

    /// Sets the ClientHello fragmentation plan.
    #[must_use]
    pub fn with_fragment(mut self, fragment: Option<Fragment>) -> Self {
        self.fragment = fragment;
        self
    }

    /// Sets the TLS fingerprint profile, resolving it against netune's registry.
    ///
    /// # Errors
    ///
    /// Returns the name and the accepted set when it is not a registered preset, so a typo is a
    /// load-time error that lists the alternatives rather than a handshake that fails on the wire
    /// for a reason no log attributes to the profile.
    pub fn with_tls_profile(mut self, name: &str) -> Result<Self, ProxyProtocolError> {
        let Some(preset) = Preset::by_name(name) else {
            let known: Vec<&str> = Preset::all().iter().map(|preset| preset.name()).collect();
            return Err(ProxyProtocolError::UnsupportedLink(format!(
                "global.tls.profile = {name:?} is not a netune TLS preset; the registered names \
                 are {known:?}"
            )));
        };
        self.tls_profile = Some(preset.name());
        Ok(self)
    }

    /// The socket options this dialer would apply.
    ///
    /// Public because a datagram leg has to be configured identically: a mark or a
    /// buffer size that applied to one transport and not the other would make the
    /// two legs of the same proxy behave differently.
    #[must_use]
    pub fn socket_config(self) -> SocketConfig {
        match self.so_mark {
            Some(mark) => SocketConfig::default().with_mark(mark),
            None => SocketConfig::default(),
        }
    }
}
