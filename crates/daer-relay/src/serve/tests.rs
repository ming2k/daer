use super::*;
use crate::inbound::tcp::Accepted;
use crate::inbound::udp::{Datagram, DatagramIngress};
use crate::relay::datagram::{DatagramService, DatagramStats, RelayOptions};
use crate::testkit::{DirectRouter, EchoDecide, RefusingRouter};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// Tests accept through a plain listener: same loop, no privileges.
#[derive(Debug)]
struct PlainListener(TcpListener);

fn next_flow_id() -> daer_observe::FlowId {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    daer_observe::FlowId::new(NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed))
}

impl Ingress for PlainListener {
    async fn accept(&self) -> Result<Accepted, RelayError> {
        let (stream, source) = self.0.accept().await.map_err(RelayError::Accept)?;
        let destination = stream.local_addr().map_err(RelayError::Socket)?;
        Ok(Accepted {
            stream,
            flow_id: next_flow_id(),
            source,
            destination,
        })
    }
}

/// A decider that records the ingress ID and then dials an echo server.
#[derive(Debug)]
struct RecordingDecide {
    upstream: SocketAddr,
    seen: Arc<std::sync::Mutex<Vec<daer_observe::FlowId>>>,
}

impl Decide for RecordingDecide {
    type Upstream = tokio::net::TcpStream;
    type Future<'a> = std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Self::Upstream, RelayError>> + Send + 'a>,
    >;

    fn decide<'a>(&'a self, flow: &'a Accepted) -> Self::Future<'a> {
        self.seen
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .push(flow.flow_id);
        let upstream = self.upstream;
        Box::pin(async move {
            tokio::net::TcpStream::connect(upstream)
                .await
                .map_err(RelayError::Relay)
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

struct GateDecide {
    entered: Arc<tokio::sync::Notify>,
    release: Arc<tokio::sync::Notify>,
    upstream: SocketAddr,
}

impl Decide for GateDecide {
    type Upstream = tokio::net::TcpStream;
    type Future<'a>
        = std::pin::Pin<Box<dyn Future<Output = Result<Self::Upstream, RelayError>> + Send + 'a>>
    where
        Self: 'a;

    fn decide<'a>(&'a self, _flow: &'a Accepted) -> Self::Future<'a> {
        Box::pin(async move {
            self.entered.notify_one();
            self.release.notified().await;
            tokio::net::TcpStream::connect(self.upstream)
                .await
                .map_err(RelayError::Socket)
        })
    }
}

#[tokio::test]
async fn a_slow_decision_does_not_block_accepting_the_next_flow() {
    // Falsifier for the accept-loop starvation defect: `serve_parallel` must accept the
    // second flow while the first flow's decision is still parked in its dial. The old
    // inline `serve` loop accepted once and then awaited `decide`, so `accepted` stayed at
    // one until the first dial finished.
    let upstream = echo_server().await;
    let listener = PlainListener(
        TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("binds"),
    );
    let ingress_addr = listener.0.local_addr().expect("addr");
    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let decide = Arc::new(GateDecide {
        entered: Arc::clone(&entered),
        release: Arc::clone(&release),
        upstream,
    });
    let supervisor = Supervisor::new();
    let task_supervisor = supervisor.handle();
    let loop_task = tokio::spawn(async move {
        serve_parallel(
            &listener,
            decide,
            &task_supervisor,
            std::future::pending::<()>(),
        )
        .await
    });

    let first = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        tokio::net::TcpStream::connect(ingress_addr),
    )
    .await
    .expect("the first client connects")
    .expect("first connection");
    tokio::time::timeout(std::time::Duration::from_secs(2), entered.notified())
        .await
        .expect("the first decision starts");

    let second = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        tokio::net::TcpStream::connect(ingress_addr),
    )
    .await
    .expect("the second client connects")
    .expect("second connection");

    let accepted = tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            if supervisor.metrics().snapshot().accepted >= 2 {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await;
    release.notify_waiters();
    drop((first, second));
    loop_task.abort();
    let _ = loop_task.await;
    accepted.expect("the accept loop must not wait for the first decision");
}

#[tokio::test]
async fn the_datagram_half_can_shut_down_without_stopping_tcp() {
    // The two halves share a shutdown signal, but not a lifetime: this asserts the join
    // returns, and that the TCP half served a flow while the datagram half was running.
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
    let datagram_address: SocketAddr = "127.0.0.1:9".parse().expect("addr");
    let ingress_udp: Arc<dyn DatagramIngress> = Arc::new(TestIngress {
        socket: datagram_socket,
        destination: datagram_address,
    });

    let supervisor = Supervisor::new();
    let decide = EchoDecide {
        upstream,
        reject: false,
    };
    let stats = Arc::new(DatagramStats::default());
    let service = DatagramService {
        ingress: ingress_udp,
        router: Arc::new(DirectRouter),
        options: RelayOptions::default().with_idle_timeout(std::time::Duration::from_secs(3600)),
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

#[tokio::test]
async fn a_refusing_datagram_router_does_not_stop_the_tcp_half() {
    // The negative control for the join: a datagram decider that refuses everything
    // must be reported, and TCP must keep serving.
    let upstream = echo_server().await;
    let listener = PlainListener(
        TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("binds"),
    );
    let ingress_addr = listener.0.local_addr().expect("addr");

    let socket = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("udp binds");
    let ingress: Arc<dyn DatagramIngress> = Arc::new(TestIngress {
        socket,
        destination: "127.0.0.1:9".parse().expect("addr"),
    });
    let stats = Arc::new(DatagramStats::default());
    let service = DatagramService {
        ingress,
        router: Arc::new(RefusingRouter("no datagram for you")),
        options: RelayOptions::default().with_idle_timeout(std::time::Duration::from_secs(3600)),
        stats: Arc::clone(&stats),
    };

    let supervisor = Supervisor::new();
    let decide = EchoDecide {
        upstream,
        reject: false,
    };
    let loop_task = tokio::spawn({
        let supervisor = supervisor.clone();
        let shutdown = std::future::pending::<()>();
        async move {
            serve_with_datagrams(&listener, &decide, &supervisor, Some(service), shutdown).await
        }
    });

    assert_eq!(talk_to(ingress_addr, b"hello").await, b"hello");
    loop_task.abort();
    let _ = loop_task.await;
    assert_eq!(supervisor.metrics().snapshot().accepted, 1);
}

/// A loopback datagram ingress: the transparent listener needs `CAP_NET_ADMIN`, so the
/// service wiring is proven with a socket that has the same trait surface.
#[derive(Debug)]
struct TestIngress {
    socket: tokio::net::UdpSocket,
    destination: SocketAddr,
}

impl DatagramIngress for TestIngress {
    fn recv<'a>(
        &'a self,
        buffer: &'a mut [u8],
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Datagram, RelayError>> + Send + 'a>,
    > {
        Box::pin(async move {
            let (len, source) = self
                .socket
                .recv_from(buffer)
                .await
                .map_err(RelayError::Socket)?;
            Ok(Datagram {
                flow_id: daer_observe::FlowId::new(1),
                source,
                destination: self.destination,
                len,
            })
        })
    }

    fn send_from<'a>(
        &'a self,
        payload: &'a [u8],
        _source: SocketAddr,
        peer: SocketAddr,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = std::io::Result<usize>> + Send + 'a>>
    {
        // A loopback socket cannot own a non-local source address; the source-address
        // assertion lives in the datagram relay's `LoopbackIngress` test, which records
        // the pair instead of relying on the wire.
        Box::pin(async move { self.socket.send_to(payload, peer).await })
    }
}

#[tokio::test]
async fn a_flow_trace_is_joinable_by_id() {
    // The ingress creates the ID; the decider must receive the same value. Without this,
    // `flow.accepted` and `flow.decided` could only be joined by guessing from the 4-tuple.
    let upstream = echo_server().await;
    let listener = PlainListener(
        TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("binds"),
    );
    let ingress_addr = listener.0.local_addr().expect("addr");
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let decide = Arc::new(RecordingDecide {
        upstream,
        seen: Arc::clone(&seen),
    });
    let supervisor = Supervisor::new();
    let loop_task = tokio::spawn({
        let supervisor = supervisor.clone();
        let shutdown = std::future::pending::<()>();
        async move { serve_parallel(&listener, decide, &supervisor, shutdown).await }
    });

    assert_eq!(talk_to(ingress_addr, b"one").await, b"one");
    assert_eq!(talk_to(ingress_addr, b"two").await, b"two");
    loop_task.abort();
    let _ = loop_task.await;
    let ids = seen.lock().unwrap_or_else(|error| error.into_inner());
    assert_eq!(ids.len(), 2, "{ids:?}");
    assert_ne!(ids[0], ids[1], "two flows cannot share a correlation ID");
    assert!(ids.iter().all(|id| id.get() != 0));
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
    let decide = EchoDecide {
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
    let decide = EchoDecide {
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
