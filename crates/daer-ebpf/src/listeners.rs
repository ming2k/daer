// SPDX-License-Identifier: AGPL-3.0-only

//! The sockets the datapath hands a redirected flow to.
//!
//! `listen_socket_map` is a `SOCKMAP` keyed by family, and the keys are the C's own:
//! `0` is tcp4, `1` is udp, `2` is tcp6 (see `assign_listener` in `tproxy.c`). This type is
//! the only place those three fds travel together, so a caller cannot publish two of them
//! and forget the third — which is exactly how UDP came to be silently dropped on the eBPF
//! path: the map was written for TCP only, `assign_listener(skb, IPPROTO_UDP)` returned
//! `-1`, and the datagram was shot after the datapath had already decided to proxy it.
//!
//! The fds are borrowed, not owned: they belong to the daemon's listeners, and the kernel
//! takes its own reference when the fd is written into the map.

use std::os::fd::RawFd;

/// The three listener fds the datapath may assign a redirected flow to.
///
/// # Why this is not `Option`
///
/// A missing UDP socket is not a "TCP-only deployment": with the datapath attached, a UDP
/// packet is redirected regardless, and a listener map without key `1` turns that redirect
/// into a silent drop. A deployment that genuinely has no UDP socket must not attach the
/// datapath at all, and saying so is the caller's job (see `daer run --no-datapath`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Listeners {
    /// IPv4 TCP listener, key `0`.
    pub tcp4: RawFd,
    /// The transparent UDP socket, key `1`.
    pub udp: RawFd,
    /// IPv6 TCP listener, key `2`.
    pub tcp6: RawFd,
}

impl Listeners {
    /// The three entries as `(key, fd, name)`, in the order the C declares them.
    ///
    /// One function rather than three literals at the publish site: the keys are ABI, and a
    /// second copy of them is a second thing to get wrong.
    pub(crate) fn entries(&self) -> [(u32, RawFd, &'static str); 3] {
        [
            (0, self.tcp4, "tcp4"),
            (1, self.udp, "udp"),
            (2, self.tcp6, "tcp6"),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_keys_match_the_c_listener_slots() {
        // The C indexes `listen_socket_map` with `zero_key`/`one_key`/`two_key`, where TCP
        // picks 0 or 2 by family and UDP is always 1. A reordering here would assign a TCP
        // socket to a datagram.
        let listeners = Listeners {
            tcp4: 10,
            udp: 11,
            tcp6: 12,
        };
        assert_eq!(
            listeners.entries(),
            [(0, 10, "tcp4"), (1, 11, "udp"), (2, 12, "tcp6")]
        );
    }
}
