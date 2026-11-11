// SPDX-License-Identifier: AGPL-3.0-only

//! The sockets the datapath hands a redirected flow to.
//!
//! `listen_socket_map` is a `SOCKMAP` keyed by protocol and family, and the keys are the C's
//! own: `0` is tcp4, `1` is udp4, `2` is tcp6, `3` is udp6 (see `assign_listener` in
//! `redirect.h`). This type is the only place those four fds travel together, so a caller
//! cannot publish three of them and forget the fourth — which is exactly how UDP came to be
//! silently dropped on the eBPF path: the map was written for TCP only,
//! `assign_listener(skb, IPPROTO_UDP)` returned `-1`, and the datagram was shot after the
//! datapath had already decided to proxy it.
//!
//! The fds are borrowed, not owned: they belong to the daemon's listeners, and the kernel
//! takes its own reference when the fd is written into the map.

use std::os::fd::RawFd;

/// The four listener fds the datapath may assign a redirected flow to.
///
/// # Why this is not `Option`
///
/// A missing UDP socket is not a "TCP-only deployment": with the datapath attached, a UDP
/// packet is redirected regardless, and a listener map without its slot turns that redirect
/// into a silent drop. A deployment that genuinely has no UDP socket must not attach the
/// datapath at all, and saying so is the caller's job (see `daer run --no-datapath`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Listeners {
    /// IPv4 TCP listener, key `0`.
    pub tcp4: RawFd,
    /// IPv4 UDP listener, key `1`.
    pub udp4: RawFd,
    /// IPv6 TCP listener, key `2`.
    pub tcp6: RawFd,
    /// IPv6 UDP listener, key `3`.
    pub udp6: RawFd,
}

impl Listeners {
    /// The four entries as `(key, fd, name)`, in the order the C declares them.
    ///
    /// One function rather than four literals at the publish site: the keys are ABI, and a
    /// second copy of them is a second thing to get wrong.
    pub(crate) fn entries(&self) -> [(u32, RawFd, &'static str); 4] {
        [
            (0, self.tcp4, "tcp4"),
            (1, self.udp4, "udp4"),
            (2, self.tcp6, "tcp6"),
            (3, self.udp6, "udp6"),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_keys_match_the_c_listener_slots() {
        // The C indexes `listen_socket_map` by protocol and family. A reordering here would
        // assign a TCP socket to a datagram, or a v4 socket to a v6 flow.
        let listeners = Listeners {
            tcp4: 10,
            udp4: 11,
            tcp6: 12,
            udp6: 13,
        };
        assert_eq!(
            listeners.entries(),
            [
                (0, 10, "tcp4"),
                (1, 11, "udp4"),
                (2, 12, "tcp6"),
                (3, 13, "udp6"),
            ]
        );
    }
}
