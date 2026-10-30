// SPDX-License-Identifier: AGPL-3.0-only

//! The accept loop.
//!
//! # Shape
//!
//! [`serve`] takes *something that accepts* and *something that decides*, and does
//! the rest: run the decision, splice the flow, keep accepting.
//!
//! The two parts are traits rather than concrete types for one reason — the loop is
//! the part that is easy to get wrong (resource exhaustion, a panicking handler, a
//! handler that never returns) and it must be testable without `CAP_NET_ADMIN`.
//! Tests drive it through a plain listener; production drives it through
//! [`TransparentListener`](crate::inbound::TransparentListener).
//!
//! # Rules the loop enforces
//!
//! * **A rejection closes one connection, never the loop.** Unsolicited traffic
//!   aimed at the transparent port is expected, not exceptional.
//! * **Resource exhaustion backs off.** `EMFILE`/`ENFILE`/`ENOBUFS`/`ENOMEM` mean
//!   "try again shortly"; tearing the loop down would blackhole the port until the
//!   next restart.
//! * **A flow cannot take the process down.** Each connection runs in its own task,
//!   so a panic is that task's failure.
//! * **Cancellation is dropping.** Dropping the future returned by [`serve`] aborts
//!   the loop and every in-flight flow, with nothing left running.

use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};

use crate::datagram::{DatagramService, serve_datagrams};
use crate::error::{IngressError, Reject};
use crate::inbound::Accepted;
use crate::relay::{Relayed, splice};
use crate::supervise::Supervisor;

/// Where flows come from.
///
/// Implemented by the transparent listener in production and by a plain listener in
/// tests. Returning [`Reject`] is not an error: it means "this flow is not ours".
pub trait Ingress {
    /// The next flow, or an error that the loop has to classify.
    fn accept(&self) -> impl Future<Output = Result<Accepted, IngressError>> + Send;
}

/// What to do with an accepted flow.
///
/// The implementation owns the routing decision and the dial, so this crate stays
/// free of transport and of netune: the returned stream is simply the other leg to
/// splice to.
pub trait Decide {
    /// The outbound leg to splice into. `Send` because each flow runs in its own
    /// task: a blocking stream here would pin the whole accept loop.
    type Upstream: AsyncRead + AsyncWrite + Unpin + Send + 'static;

    /// The future produced per flow.
    type Future<'a>: Future<Output = Result<Self::Upstream, IngressError>> + Send + 'a
    where
        Self: 'a;

    /// Resolves the flow's destination and opens the other leg.
    ///
    /// Both borrows share one lifetime: the returned future may keep reading the
    /// flow (its addresses) and the router (the compiled program) until it
    /// resolves, and tying them together is what lets an implementation be a plain
    /// `async fn` call rather than a hand-rolled state machine.
    fn decide<'a>(&'a self, flow: &'a Accepted) -> Self::Future<'a>;
}

/// Backoff after `accept(2)` fails because a resource is exhausted.
const EXHAUSTION_BACKOFF: Duration = Duration::from_millis(20);

/// Why an accept loop stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stopped {
    /// Nothing is accepting any more; the flows spawned by this loop may still be
    /// relaying under the [`Supervisor`].
    Accepting(ShutdownReason),
}

/// What told the loop to stop accepting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShutdownReason {
    /// Shutdown was requested: stop accepting, keep the live flows.
    ///
    /// This is the reload case and the graceful-stop case. The distinction that
    /// matters is *accepting* versus *relaying*, and only accepting stops.
    Requested,
    /// The listener itself is gone (its last handle dropped).
    ListenerClosed,
}

/// Runs the accept loop until the listener is closed or shutdown is requested.
///
/// `shutdown` is resolved by dropping it (`tokio::select!`), which is how a
/// `CancellationToken` and a one-shot channel both work. Live flows are owned by
/// `supervisor`, so **this loop ending does not end them**: that is what makes a
/// reload able to swap the loop without dropping a connection.
///
/// # Errors
///
/// Returns [`IngressError`] for an accept failure that is not resource exhaustion.
/// Per-connection failures are counted, not returned: one broken flow must not end
/// the service.
pub async fn serve<I, D>(
    ingress: &I,
    decide: &D,
    supervisor: &Supervisor,
    shutdown: impl Future<Output = ()>,
) -> Result<Stopped, IngressError>
where
    I: Ingress + Sync,
    D: Decide + Sync,
{
    let metrics = supervisor.metrics();
    tokio::pin!(shutdown);

    loop {
        let flow = match tokio::select! {
            () = &mut shutdown => {
                let in_flight = supervisor.in_flight();
                tracing::info!(
                    in_flight,
                    "stopped accepting; live flows keep relaying"
                );
                return Ok(Stopped::Accepting(ShutdownReason::Requested));
            }
            accepted = ingress.accept() => accepted,
        } {
            Ok(flow) => flow,
            Err(IngressError::Rejected(reject)) => {
                metrics.rejected.fetch_add(1, Ordering::Relaxed);
                tracing::debug!(%reject, "dropped a flow that was not redirected");
                continue;
            }
            Err(IngressError::Accept(error)) if is_resource_exhausted(&error) => {
                metrics.exhausted.fetch_add(1, Ordering::Relaxed);
                tracing::warn!(%error, "accept failed on a resource limit; backing off");
                tokio::time::sleep(EXHAUSTION_BACKOFF).await;
                continue;
            }
            Err(error) => return Err(error),
        };

        metrics.accepted.fetch_add(1, Ordering::Relaxed);
        let upstream = match decide.decide(&flow).await {
            Ok(upstream) => upstream,
            Err(error) => {
                metrics.failed.fetch_add(1, Ordering::Relaxed);
                tracing::debug!(%error, destination = %flow.destination, "no outbound leg");
                continue;
            }
        };

        // The relay owns both halves from here, and the supervisor owns the relay:
        // the loop keeps accepting, and stopping the loop leaves this flow running.
        supervisor.spawn(async move {
            match splice(flow.stream, upstream).await {
                Ok(relayed) => {
                    tracing::debug!(
                        destination = %flow.destination,
                        to_upstream = relayed.to_upstream,
                        to_client = relayed.to_client,
                        elapsed_ms = relayed.elapsed.as_millis(),
                        "flow closed"
                    );
                    relayed
                }
                Err(error) => {
                    tracing::debug!(%error, destination = %flow.destination, "relay failed");
                    Relayed::default()
                }
            }
        });
    }
}

/// Live counters for the accept loop.
///
/// Atomic rather than returned: the loop is long-lived, so its counters have to be
/// readable at any moment, including right before a shutdown.
#[derive(Debug, Default)]
pub struct Metrics {
    accepted: AtomicU64,
    rejected: AtomicU64,
    failed: AtomicU64,
    exhausted: AtomicU64,
    panicked: AtomicU64,
}

impl Metrics {
    /// Increments one counter.
    ///
    /// Takes the counter itself rather than a name so a typo is a compile error, and
    /// so callers outside this module (the flow supervisor) can attribute an event
    /// without a match on a string.
    pub(crate) fn bump(&self, counter: &AtomicU64) {
        counter.fetch_add(1, Ordering::Relaxed);
    }

    /// Records a flow that ended without finishing its work.
    pub(crate) fn record_abnormal_end(&self) {
        self.bump(&self.panicked);
    }

    /// A consistent-enough point-in-time snapshot.
    #[must_use]
    pub fn snapshot(&self) -> ServeStats {
        ServeStats {
            accepted: self.accepted.load(Ordering::Relaxed),
            rejected: self.rejected.load(Ordering::Relaxed),
            failed: self.failed.load(Ordering::Relaxed),
            exhausted: self.exhausted.load(Ordering::Relaxed),
            panicked: self.panicked.load(Ordering::Relaxed),
        }
    }
}

/// Counters for what the loop has seen.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ServeStats {
    /// Flows accepted from the ingress.
    pub accepted: u64,
    /// Flows dropped because they were not redirected by the datapath.
    pub rejected: u64,
    /// Flows whose outbound leg could not be opened.
    pub failed: u64,
    /// Accept failures caused by a resource limit, retried after a backoff.
    pub exhausted: u64,
    /// Flow tasks that ended by panicking.
    pub panicked: u64,
}

/// Runs the TCP accept loop and a datagram relay together, until `shutdown` resolves.
///
/// The two halves have different lifetimes by design, so this is a `join` and not a
/// merge: a TCP flow ends with its relay, a datagram session ends with its idle
/// timeout, and neither may be bound to the other's shutdown. Both stop *accepting*
/// together, which is all a reload needs.
///
/// A datagram relay that fails is reported and does not stop TCP: the two are
/// independent services sharing a configuration generation, and silencing HTTP because
/// a UDP socket misbehaved would be a worse failure than the one being reported.
///
/// # Errors
///
/// Returns the first TCP accept failure that is not resource exhaustion, per
/// [`serve`]. A datagram failure is logged rather than returned.
pub async fn serve_with_datagrams<I, D>(
    ingress: &I,
    decide: &D,
    supervisor: &Supervisor,
    datagrams: Option<DatagramService>,
    shutdown: impl Future<Output = ()> + Clone,
) -> Result<Stopped, IngressError>
where
    I: Ingress + Sync,
    D: Decide + Sync,
{
    let Some(service) = datagrams else {
        return serve(ingress, decide, supervisor, shutdown).await;
    };

    let datagram_shutdown = shutdown.clone();
    let relay = async move {
        let result = serve_datagrams(
            service.ingress,
            service.router,
            service.options,
            service.stats,
            datagram_shutdown,
        )
        .await;
        if let Err(error) = result {
            tracing::warn!(%error, "datagram relay stopped");
        }
    };

    let (stopped, ()) = tokio::join!(serve(ingress, decide, supervisor, shutdown), relay);
    stopped
}

/// True for `accept(2)` failures that mean "out of file descriptors or memory".
///
/// Retrying is the only sane response: the condition is transient under load, and
/// exiting would leave the transparent port unserved.
#[must_use]
pub fn is_resource_exhausted(error: &std::io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(libc::EMFILE) | Some(libc::ENFILE) | Some(libc::ENOBUFS) | Some(libc::ENOMEM)
    )
}

/// Convenience for a rejection without an accepted flow.
#[must_use]
pub fn reject(destination: std::net::SocketAddr) -> IngressError {
    IngressError::Rejected(Reject::SelfConnect { destination })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inbound::Accepted;
    use std::net::{Ipv4Addr, SocketAddr};
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// Tests accept through a plain listener: same loop, no privileges.
    struct PlainListener(TcpListener);

    impl Ingress for PlainListener {
        async fn accept(&self) -> Result<Accepted, IngressError> {
            let (stream, source) = self.0.accept().await.map_err(IngressError::Accept)?;
            let destination = stream.local_addr().map_err(IngressError::Socket)?;
            Ok(Accepted {
                stream,
                source,
                destination,
            })
        }
    }

    /// Dials a fixed echo server, so the test has a real upstream to splice to.
    struct EchoRouter {
        upstream: SocketAddr,
        reject: bool,
    }

    impl Decide for EchoRouter {
        type Upstream = tokio::net::TcpStream;
        type Future<'a> = std::pin::Pin<
            Box<dyn Future<Output = Result<Self::Upstream, IngressError>> + Send + 'a>,
        >;

        fn decide<'a>(&'a self, flow: &'a Accepted) -> Self::Future<'a> {
            let upstream = self.upstream;
            let should_reject = self.reject;
            let destination = flow.destination;
            Box::pin(async move {
                if should_reject {
                    return Err(super::reject(destination));
                }
                tokio::net::TcpStream::connect(upstream)
                    .await
                    .map_err(IngressError::Relay)
            })
        }
    }

    async fn echo_server() -> SocketAddr {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("binds");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            loop {
                let (mut stream, _) = match listener.accept().await {
                    Ok(pair) => pair,
                    Err(_) => return,
                };
                tokio::spawn(async move {
                    let mut buffer = vec![0u8; 256];
                    while let Ok(read) = stream.read(&mut buffer).await {
                        if read == 0 {
                            return;
                        }
                        if stream.write_all(&buffer[..read]).await.is_err() {
                            return;
                        }
                    }
                });
            }
        });
        addr
    }

    async fn talk_to(addr: SocketAddr, payload: &[u8]) -> Vec<u8> {
        let mut client = tokio::net::TcpStream::connect(addr)
            .await
            .expect("connects");
        client.write_all(payload).await.expect("writes");
        let mut received = vec![0u8; payload.len()];
        client
            .read_exact(&mut received)
            .await
            .expect("reads the echo");
        received
    }

    #[tokio::test]
    async fn the_datagram_half_can_shut_down_without_stopping_tcp() {
        // The two halves share a configuration generation and a shutdown signal, but not
        // a lifetime: this asserts the join returns, and that the TCP half served a flow
        // while the datagram half was running.
        let upstream = echo_server().await;
        let listener = PlainListener(
            TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .expect("binds"),
        );
        let ingress_addr = listener.0.local_addr().expect("addr");

        let datagram_socket = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("udp binds");
        let datagram_address: std::net::SocketAddr = "127.0.0.1:9".parse().expect("addr");
        let ingress_udp: Arc<dyn crate::ingress_udp::DatagramIngress> = Arc::new(TestIngress {
            socket: datagram_socket,
            destination: datagram_address,
        });

        let supervisor = Supervisor::new();
        let decide = EchoRouter {
            upstream,
            reject: false,
        };
        let stats = Arc::new(crate::datagram::DatagramStats::default());
        let service = crate::datagram::DatagramService {
            ingress: ingress_udp,
            router: Arc::new(test_router()),
            options: crate::datagram::RelayOptions::default()
                .with_idle_timeout(std::time::Duration::from_secs(3600)),
            stats: Arc::clone(&stats),
        };

        let loop_task = tokio::spawn({
            let supervisor = supervisor.clone();
            let shutdown = std::future::pending::<()>();
            async move {
                serve_with_datagrams(&listener, &decide, &supervisor, Some(service), shutdown).await
            }
        });

        // TCP still works while the relay runs.
        assert_eq!(talk_to(ingress_addr, b"hello").await, b"hello");

        loop_task.abort();
        let _ = loop_task.await;
        assert_eq!(supervisor.metrics().snapshot().accepted, 1);
        // No datagram traffic happened, so the relay must not have invented sessions.
        assert_eq!(stats.snapshot().sessions_opened, 0);
    }

    /// A loopback datagram ingress: the transparent listener needs `CAP_NET_ADMIN`, so the
    /// service wiring is proven with a socket that has the same trait surface.
    #[derive(Debug)]
    struct TestIngress {
        socket: tokio::net::UdpSocket,
        destination: std::net::SocketAddr,
    }

    impl crate::ingress_udp::DatagramIngress for TestIngress {
        fn recv<'a>(
            &'a self,
            buffer: &'a mut [u8],
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<Output = Result<crate::ingress_udp::Datagram, IngressError>>
                    + Send
                    + 'a,
            >,
        > {
            Box::pin(async move {
                let (len, source) = self
                    .socket
                    .recv_from(buffer)
                    .await
                    .map_err(IngressError::Socket)?;
                Ok(crate::ingress_udp::Datagram {
                    source,
                    destination: self.destination,
                    len,
                })
            })
        }

        fn send_to<'a>(
            &'a self,
            payload: &'a [u8],
            peer: std::net::SocketAddr,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = std::io::Result<usize>> + Send + 'a>>
        {
            Box::pin(async move { self.socket.send_to(payload, peer).await })
        }
    }

    fn test_router() -> crate::decide::Router {
        let config = daer_config::toml_config::load_str(
            "schema = 1\n\n[routing]\nrules = []\nfallback = \"direct\"\n",
        )
        .expect("config loads");
        crate::decide::Router::new(
            &config,
            crate::GenerationId::new(1),
            &crate::RouterOptions::default(),
        )
        .expect("router builds")
    }

    #[tokio::test]
    async fn serves_a_flow_end_to_end() {
        let upstream = echo_server().await;
        let listener = PlainListener(
            TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .expect("binds"),
        );
        let ingress_addr = listener.0.local_addr().expect("addr");

        let supervisor = Supervisor::new();
        let decide = EchoRouter {
            upstream,
            reject: false,
        };
        let loop_task = tokio::spawn({
            let supervisor = supervisor.clone();
            let shutdown = std::future::pending::<()>();
            async move { serve(&listener, &decide, &supervisor, shutdown).await }
        });

        assert_eq!(talk_to(ingress_addr, b"hello").await, b"hello");
        assert_eq!(talk_to(ingress_addr, b"again").await, b"again");

        // Dropping the loop future is the shutdown mechanism; nothing may hang.
        loop_task.abort();
        let _ = loop_task.await;

        let stats = supervisor.metrics().snapshot();
        assert_eq!(stats.accepted, 2, "{stats:?}");
        assert_eq!(stats.failed, 0, "{stats:?}");
    }

    #[tokio::test]
    async fn a_rejected_flow_does_not_end_the_loop() {
        let upstream = echo_server().await;
        let listener = PlainListener(
            TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .expect("binds"),
        );
        let ingress_addr = listener.0.local_addr().expect("addr");

        // First flow is rejected, so the client sees a closed connection.
        let decide = EchoRouter {
            upstream,
            reject: true,
        };
        let supervisor = Supervisor::new();
        let loop_task = tokio::spawn({
            let supervisor = supervisor.clone();
            let shutdown = std::future::pending::<()>();
            async move { serve(&listener, &decide, &supervisor, shutdown).await }
        });

        let mut client = tokio::net::TcpStream::connect(ingress_addr)
            .await
            .expect("connects");
        client.write_all(b"dropped").await.expect("writes");
        let mut sink = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(2), client.read_to_end(&mut sink))
            .await
            .expect("the rejected flow must be closed, not left open");

        loop_task.abort();
        let _ = loop_task.await;

        let stats = supervisor.metrics().snapshot();
        assert_eq!(stats.accepted, 1, "{stats:?}");
        assert_eq!(stats.failed, 1, "{stats:?}");
    }

    #[test]
    fn classifies_resource_exhaustion() {
        for code in [libc::EMFILE, libc::ENFILE, libc::ENOBUFS, libc::ENOMEM] {
            assert!(is_resource_exhausted(&std::io::Error::from_raw_os_error(
                code
            )));
        }
        assert!(!is_resource_exhausted(&std::io::Error::from_raw_os_error(
            libc::EINVAL
        )));
    }
}
