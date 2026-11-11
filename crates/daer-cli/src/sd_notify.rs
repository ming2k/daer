// SPDX-License-Identifier: AGPL-3.0-only

//! The small part of `sd_notify(3)` the daemon needs, without linking `libsystemd`.
//!
//! # Why this exists
//!
//! The shipped unit is `Type=notify`: systemd must not call the service "started" until the
//! configuration has loaded, the private ingress exists, the listeners are bound and the
//! datapath is attached. With `Type=simple` the same daemon was reported active immediately,
//! so an operator (or a dependency unit) could use a proxy that had not started proxying yet.
//! Readiness is therefore a daemon-side fact, not something the unit can infer from `execve`.
//!
//! The protocol itself is one datagram sent to `$NOTIFY_SOCKET` with newline-separated
//! `KEY=value` fields. Pulling in `libsystemd` (or a wrapper crate) for that would add a
//! build-time dependency whose only job is to write those bytes; the socket is already
//! permitted by the unit's `RestrictAddressFamilies=… AF_UNIX …`.
//!
//! # Manual runs
//!
//! When `NOTIFY_SOCKET` is unset, every method is a no-op. `daer run` is a normal foreground
//! process outside systemd, and requiring a notification socket would make it unusable there.

use std::ffi::OsStr;
use std::io;
use std::os::unix::net::{SocketAddr, UnixDatagram};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

/// A sender for systemd status notifications.
///
/// Cheap to clone: every clone names the same socket. A disabled notifier (the manual-run
/// case) carries no socket and silently drops messages.
#[derive(Debug, Clone)]
pub struct Notifier {
    inner: Option<Arc<NotifySocket>>,
}

#[derive(Debug)]
struct NotifySocket {
    datagram: UnixDatagram,
    address: SocketAddr,
}

impl Notifier {
    /// Builds a notifier from `$NOTIFY_SOCKET`, or a disabled one when it is unset.
    ///
    /// An unreadable or invalid socket is not fatal: the daemon must still run when started
    /// by hand, and a notification failure must never take down the proxy it describes.
    #[must_use]
    pub fn from_env() -> Self {
        let Some(raw) = std::env::var_os("NOTIFY_SOCKET") else {
            return Self::disabled();
        };
        if raw.is_empty() {
            return Self::disabled();
        }
        match notify_address(&raw).and_then(NotifySocket::new) {
            Ok(socket) => Self {
                inner: Some(Arc::new(socket)),
            },
            Err(error) => {
                // Before `init_logging`, this line is intentionally unseen. The failure is
                // still harmless: the service runs, only its status updates are missing.
                daer_observe::debug!(daer_observe::EventCode::DaemonSdNotifyDisabled,
                    %error,
                    "NOTIFY_SOCKET is not usable; systemd notifications are disabled"
                );
                Self::disabled()
            }
        }
    }

    /// A notifier that sends nothing.
    #[must_use]
    pub fn disabled() -> Self {
        Self { inner: None }
    }

    /// True when status datagrams will actually be sent.
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.inner.is_some()
    }

    /// A free-form status line shown by `systemctl status`.
    pub fn status(&self, text: &str) {
        self.send(&message(&[("STATUS", text)]));
    }

    /// Reports that the daemon is ready to serve, and sets its status in the same datagram.
    ///
    /// `READY=1` is the transition systemd waits for under `Type=notify`. Sending it before
    /// the listeners and datapath exist would reproduce the `Type=simple` defect with extra
    /// steps, so call sites send this only after the serving state is complete.
    pub fn ready(&self, text: &str) {
        self.send(&message(&[("READY", "1"), ("STATUS", text)]));
    }

    /// Reports that a `SIGHUP` reload has started.
    pub fn reloading(&self) {
        self.send(&message(&[
            ("RELOADING", "1"),
            ("STATUS", "reloading configuration"),
        ]));
    }

    /// Reports that shutdown has started, so systemd can show "deactivating" immediately.
    pub fn stopping(&self, text: &str) {
        self.send(&message(&[("STOPPING", "1"), ("STATUS", text)]));
    }

    /// Feeds the service watchdog. Ignored when `WatchdogSec=` is not configured.
    pub fn watchdog(&self) {
        self.send(&message(&[("WATCHDOG", "1")]));
    }

    /// Asks systemd to extend the current start/stop/reload timeout by `extra`.
    ///
    /// Used during shutdown when the operator configured a drain grace period longer than the
    /// unit's `TimeoutStopSec`: the daemon is still doing useful work and must not be killed
    /// before its own bound is reached.
    pub fn extend_timeout(&self, extra: Duration) {
        let micros = u64::try_from(extra.as_micros()).unwrap_or(u64::MAX);
        let value = micros.to_string();
        self.send(&message(&[("EXTEND_TIMEOUT_USEC", &value)]));
    }

    /// Starts the watchdog pings when systemd asked for them.
    ///
    /// Returns `None` when `WATCHDOG_USEC` is absent, zero, disabled, or addressed to another
    /// process. The returned guard stops the pinging task when dropped.
    #[must_use]
    pub fn watchdog_handle(&self) -> Option<Watchdog> {
        if !self.is_enabled() {
            return None;
        }
        let micros = std::env::var("WATCHDOG_USEC").ok()?.parse::<u64>().ok()?;
        if micros == 0 {
            return None;
        }
        if let Some(pid) = std::env::var_os("WATCHDOG_PID") {
            // systemd sets this when the notification socket is inherited by several
            // processes. A mismatch means the watchdog is not ours to feed.
            if pid.to_str().and_then(|value| value.parse::<u32>().ok()) != Some(std::process::id())
            {
                return None;
            }
        }

        // Half the declared interval is the documented liveness margin: one dropped ping
        // still leaves time for the next one to arrive before systemd declares a hang.
        let period = Duration::from_micros((micros / 2).max(1));
        let notifier = self.clone();
        let task = tokio::spawn(async move {
            loop {
                tokio::time::sleep(period).await;
                notifier.watchdog();
            }
        });
        Some(Watchdog { task })
    }

    fn send(&self, payload: &str) {
        let Some(inner) = &self.inner else {
            return;
        };
        if let Err(error) = inner
            .datagram
            .send_to_addr(payload.as_bytes(), &inner.address)
        {
            // `WouldBlock` means the notification queue is full. Status is best-effort and
            // must never block the daemon, so it is dropped rather than retried.
            if error.kind() != io::ErrorKind::WouldBlock {
                daer_observe::debug!(daer_observe::EventCode::DaemonSdNotifyFailed,%error, "could not send a systemd notification");
            }
        }
    }
}

/// Keeps the watchdog task alive, and stops it on the way out.
#[derive(Debug)]
pub struct Watchdog {
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Watchdog {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl NotifySocket {
    fn new(address: SocketAddr) -> io::Result<Self> {
        let datagram = UnixDatagram::unbound()?;
        // A status datagram is never worth blocking the control plane for. A full queue is
        // dropped by `Notifier::send`.
        datagram.set_nonblocking(true)?;
        Ok(Self { datagram, address })
    }
}

/// Parses `$NOTIFY_SOCKET`, including systemd's `@`-prefixed abstract namespace form.
fn notify_address(raw: &OsStr) -> io::Result<SocketAddr> {
    let bytes = raw.as_encoded_bytes();
    if let Some(name) = bytes.strip_prefix(b"@") {
        #[cfg(target_os = "linux")]
        {
            use std::os::linux::net::SocketAddrExt;
            return SocketAddr::from_abstract_name(name);
        }
        #[cfg(not(target_os = "linux"))]
        {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "abstract unix sockets are Linux-only",
            ));
        }
    }
    SocketAddr::from_pathname(Path::new(raw))
}

/// Formats one notification datagram.
///
/// Values are single-line by contract; a newline inside `STATUS` would end that field and
/// start a key systemd never asked for, so line breaks are folded to spaces.
fn message(fields: &[(&str, &str)]) -> String {
    let mut message = String::new();
    for (key, value) in fields {
        message.push_str(key);
        message.push('=');
        message.extend(value.chars().map(|character| match character {
            '\n' | '\r' => ' ',
            other => other,
        }));
        message.push('\n');
    }
    message
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn a_notification_is_newline_separated_key_value_fields() {
        assert_eq!(
            message(&[("READY", "1"), ("STATUS", "serving")]),
            "READY=1\nSTATUS=serving\n"
        );
    }

    #[test]
    fn a_status_value_cannot_smuggle_extra_fields() {
        assert_eq!(
            message(&[("STATUS", "first\nWATCHDOG=1\rsecond")]),
            "STATUS=first WATCHDOG=1 second\n"
        );
    }

    #[test]
    fn a_disabled_notifier_drops_messages_without_a_socket() {
        // The manual-run path: every method must be safe with no `$NOTIFY_SOCKET`.
        let notifier = Notifier::disabled();
        assert!(!notifier.is_enabled());
        notifier.status("ignored");
        notifier.ready("ignored");
        notifier.reloading();
        notifier.stopping("ignored");
        notifier.watchdog();
        notifier.extend_timeout(Duration::from_secs(1));
        assert!(notifier.watchdog_handle().is_none());
    }

    #[test]
    fn a_filesystem_socket_receives_the_exact_datagram() {
        let directory = std::env::temp_dir().join(format!(
            "daer-sd-notify-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&directory).expect("creates the fixture directory");
        let path = directory.join("notify.sock");
        let receiver = UnixDatagram::bind(&path).expect("binds the notification socket");
        receiver
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("sets a read timeout");

        let address = SocketAddr::from_pathname(&path).expect("builds the socket address");
        let notifier = Notifier {
            inner: Some(Arc::new(
                NotifySocket::new(address).expect("creates the sender"),
            )),
        };
        notifier.ready("serving");

        let mut buffer = [0_u8; 256];
        let received = receiver
            .recv(&mut buffer)
            .expect("receives the notification");
        assert_eq!(
            std::str::from_utf8(&buffer[..received]).expect("notification is UTF-8"),
            "READY=1\nSTATUS=serving\n"
        );

        let _ = std::fs::remove_dir_all(&directory);
    }
}
