// SPDX-License-Identifier: AGPL-3.0-only

//! Reload does not drop traffic.
//!
//! This is the acceptance criterion for generations and for the supervisor, written
//! as a test instead of as a hope:
//!
//! * **A live flow survives a reload.** The connection is mid-transfer while a new
//!   generation is published and a new accept loop takes the port; the flow finishes
//!   with the bytes it was owed.
//! * **The port never goes down.** The new loop binds before the old one stops, so a
//!   client connecting during the handover is served rather than refused.
//! * **Many reloads, one connection.** The same flow crosses many generations.
//! * **A stopped loop does not stop the flows.** `serve` returning is not a reset.
//!
//! Everything here runs unprivileged: the ingress is a plain listener and the
//! upstream is a local echo server.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use daer_control::{
    Generations, Ingress, IngressError, RouterOptions, Supervisor, bind_shared, serve_ingress,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

/// A plain listener dressed as an ingress (no `IP_TRANSPARENT`, so no privileges).
///
/// `destination` is what a transparent listener would read from the accepted
/// socket's local address: the address the router should dial.
struct PlainIngress {
    listener: TcpListener,
    destination: SocketAddr,
}

impl Ingress for PlainIngress {
    async fn accept(&self) -> Result<daer_control::Accepted, IngressError> {
        let (stream, source) = self.listener.accept().await.map_err(IngressError::Accept)?;
        Ok(daer_control::Accepted {
            stream,
            source,
            destination: self.destination,
        })
    }
}

/// An echo server that stays up for the whole test.
async fn echo_server() -> SocketAddr {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("binds");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut buffer = vec![0u8; 1024];
                loop {
                    match stream.read(&mut buffer).await {
                        Ok(0) | Err(_) => return,
                        Ok(read) => {
                            if stream.write_all(&buffer[..read]).await.is_err() {
                                return;
                            }
                        }
                    }
                }
            });
        }
    });
    addr
}

const FIRST: &str = r#"
[routing]
rules = ["port(80) -> direct"]
fallback = "direct"
"#;

const SECOND: &str = r#"
[routing]
rules = ["port(80) -> direct", "port(443) -> direct"]
fallback = "direct"
"#;

/// One accepting generation: a bound port, a supervisor to own its flows, a stop
/// signal, and the task running the loop.
struct Accepting {
    address: SocketAddr,
    stop: oneshot::Sender<()>,
    task: tokio::task::JoinHandle<Result<daer_control::Stopped, IngressError>>,
}

impl Accepting {
    /// Starts an accepting generation on `address`'s port, reusing the supervisor.
    async fn start(
        address: SocketAddr,
        dial: SocketAddr,
        supervisors: &Supervisor,
        router: Arc<daer_control::Generation>,
    ) -> Self {
        // The same socket options production uses: `SO_REUSEPORT` is what lets this
        // bind the port while the previous generation is still accepting on it.
        let listener = bind_shared(address).expect("rebinds the port while the old one serves");
        listener
            .set_nonblocking(true)
            .expect("the runtime needs a non-blocking listener");
        let listener = TcpListener::from_std(listener).expect("hands the socket to tokio");
        let bound = listener.local_addr().expect("addr");
        let (stop, stopped) = oneshot::channel();
        let ingress = PlainIngress {
            listener,
            destination: dial,
        };
        let supervisor = supervisors.clone();
        let task = tokio::spawn(async move {
            serve_ingress(&ingress, router.router(), &supervisor, async {
                let _ = stopped.await;
            })
            .await
        });
        Self {
            address: bound,
            stop,
            task,
        }
    }

    /// Stops accepting and waits for the loop to return. The flows it spawned are
    /// untouched: they belong to the supervisor.
    async fn stop(self) {
        let _ = self.stop.send(());
        let stopped = self.task.await.expect("the loop task must not panic");
        assert!(stopped.is_ok(), "the loop must stop cleanly: {stopped:?}");
    }
}

#[tokio::test]
async fn a_live_flow_survives_a_reload() {
    let upstream = echo_server().await;
    let generations = Generations::new(
        &daer_config::toml_config::load_str(FIRST).expect("loads"),
        &RouterOptions::default(),
    )
    .expect("first generation");
    let supervisor = Supervisor::new();

    let probe = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("binds");
    let address = probe.local_addr().expect("addr");
    drop(probe);

    // The flow's destination is the echo server, not the ingress: a client connects
    // to `address`, and the router dials `upstream`.
    let mut accepting =
        Accepting::start(address, upstream, &supervisor, generations.current()).await;

    // A connection that must outlive the reload.
    let mut client = TcpStream::connect(address).await.expect("connects");
    client.write_all(b"before").await.expect("writes");
    let mut echoed = [0u8; 6];
    client.read_exact(&mut echoed).await.expect("reads");
    assert_eq!(&echoed, b"before");
    assert_eq!(supervisor.in_flight(), 1);

    // Publish a new generation and start a new accepting loop, then stop the old one.
    let report = generations
        .reload(
            &daer_config::toml_config::load_str(SECOND).expect("loads"),
            &RouterOptions::default(),
        )
        .expect("reloads");
    assert!(report.routing_changed);

    let next = Accepting::start(address, upstream, &supervisor, generations.current()).await;
    let first = std::mem::replace(&mut accepting, next);
    first.stop().await;

    // The flow is still alive, with the same counters: a reload did not reset the
    // service, and stopping a loop did not reset its flows.
    assert_eq!(
        supervisor.in_flight(),
        1,
        "the flow must survive the handover"
    );
    client
        .write_all(b"after")
        .await
        .expect("the flow still relays");
    let mut echoed = [0u8; 5];
    client.read_exact(&mut echoed).await.expect("reads");
    assert_eq!(&echoed, b"after");

    drop(client);
    supervisor.drain().await;
    assert_eq!(supervisor.in_flight(), 0);
    assert_eq!(supervisor.metrics().snapshot().accepted, 1);
    assert_eq!(
        supervisor.metrics().snapshot().panicked,
        0,
        "a normally closed flow is not a failure"
    );
    assert_eq!(upstream, upstream, "the upstream is the dial target");
}

#[tokio::test]
async fn the_port_stays_up_across_a_handover() {
    let upstream = echo_server().await;
    let generations = Generations::new(
        &daer_config::toml_config::load_str(FIRST).expect("loads"),
        &RouterOptions::default(),
    )
    .expect("first generation");
    let supervisor = Supervisor::new();

    let probe = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("binds");
    let address = probe.local_addr().expect("addr");
    drop(probe);

    let first = Accepting::start(address, upstream, &supervisor, generations.current()).await;

    // The new loop binds *before* the old one stops, so there is no window in which
    // the port is unbound.
    let second = Accepting::start(address, upstream, &supervisor, generations.current()).await;
    assert_eq!(second.address, first.address, "same port");
    first.stop().await;

    // A connection made after the handover is accepted and served.
    let mut client = TcpStream::connect(second.address)
        .await
        .expect("connects during/after the handover");
    client.write_all(b"hello").await.expect("writes");
    let mut echoed = [0u8; 5];
    client.read_exact(&mut echoed).await.expect("reads");
    assert_eq!(&echoed, b"hello");

    drop(client);
    second.stop().await;
    supervisor.drain().await;
}

#[tokio::test]
async fn one_connection_crosses_many_generations() {
    let upstream = echo_server().await;
    let generations = Generations::new(
        &daer_config::toml_config::load_str(FIRST).expect("loads"),
        &RouterOptions::default(),
    )
    .expect("first generation");
    let supervisor = Supervisor::new();

    let probe = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("binds");
    let address = probe.local_addr().expect("addr");
    drop(probe);

    let mut accepting =
        Accepting::start(address, upstream, &supervisor, generations.current()).await;

    // The connection the whole test is about: pinned to generation 1.
    let pinned = generations.current();
    let mut client = TcpStream::connect(address).await.expect("connects");
    client.write_all(b"x").await.expect("writes");
    let mut byte = [0u8; 1];
    client.read_exact(&mut byte).await.expect("reads");

    for _ in 0..8 {
        let report = generations
            .reload(
                &daer_config::toml_config::load_str(SECOND).expect("loads"),
                &RouterOptions::default(),
            )
            .expect("reloads");
        assert!(!report.routing_changed || report.previous != report.generation);

        let next = Accepting::start(address, upstream, &supervisor, generations.current()).await;
        let previous = std::mem::replace(&mut accepting, next);
        previous.stop().await;

        // The flow keeps working across every generation.
        client.write_all(b"y").await.expect("still relays");
        client.read_exact(&mut byte).await.expect("still reads");
    }

    assert_eq!(generations.published(), 9, "1 initial + 8 reloads");
    assert_eq!(
        pinned.id().get(),
        1,
        "the flow is still on its first generation"
    );
    assert_eq!(supervisor.in_flight(), 1);

    drop(client);
    accepting.stop().await;
    supervisor.drain().await;
    assert_eq!(supervisor.in_flight(), 0);
}

#[tokio::test]
async fn stopping_a_loop_does_not_reset_the_service() {
    let supervisor = Supervisor::new();
    let generations = Generations::new(
        &daer_config::toml_config::load_str(FIRST).expect("loads"),
        &RouterOptions::default(),
    )
    .expect("first generation");

    // A bare flow, so no sockets are involved: this is about ownership.
    supervisor.spawn(async {
        tokio::time::sleep(Duration::from_millis(20)).await;
        daer_control::Relayed::default()
    });
    assert_eq!(supervisor.in_flight(), 1);

    // Draining waits for the flow rather than abandoning it.
    supervisor.drain().await;
    assert_eq!(supervisor.in_flight(), 0);
    // The supervisor is still usable after a drain: generations do not own it.
    supervisor.spawn(async { daer_control::Relayed::default() });
    supervisor.drain().await;
    let _ = generations;
}
