// SPDX-License-Identifier: AGPL-3.0-only

//! Runtime election control: `daer elect` and the read-only `status --nodes/--groups/--elections`
//! views.
//!
//! The daemon owns `/run/daer/admin.sock`. The CLI is a client; it never edits the
//! persistent election state or the configuration. Read views are served by the same
//! socket so a non-root operator in the admin group can inspect an election without
//! the broad, root-only status snapshot.

use std::ffi::CString;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// The daemon's writable runtime-control socket.
pub const ADMIN_SOCKET_PATH: &str = "/run/daer/admin.sock";

/// A request to the admin socket.
#[derive(Debug, Deserialize, Serialize)]
struct Request {
    command: String,
    #[serde(default)]
    election: Option<String>,
    #[serde(default)]
    node: Option<String>,
    #[serde(default)]
    view: Option<String>,
}

/// A response: either a JSON body or a structured failure.
#[derive(Debug, Serialize)]
struct Response {
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    body: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<ErrorBody>,
}

#[derive(Debug, Serialize)]
struct ErrorBody {
    code: &'static str,
    message: String,
}

fn ok(body: Value) -> Response {
    Response {
        ok: true,
        body: Some(body),
        error: None,
    }
}

fn error(code: &'static str, message: impl Into<String>) -> Response {
    Response {
        ok: false,
        body: None,
        error: Some(ErrorBody {
            code,
            message: message.into(),
        }),
    }
}

/// The admin socket path, with a test-only override.
#[must_use]
pub fn socket_path() -> PathBuf {
    std::env::var_os("DAER_ADMIN_SOCKET")
        .map_or_else(|| PathBuf::from(ADMIN_SOCKET_PATH), PathBuf::from)
}

/// Binds and serves the admin socket.
///
/// The default is **root-only**: the socket is `0600` and owned by the daemon user.
/// Non-root control is an explicit delegation, not a default: setting
/// `DAER_ADMIN_GROUP` to an existing group changes the socket to `0660` and chowns
/// it to that group. The unit must also make the daemon a member of that group
/// (`SupplementaryGroups=`) so the chown can succeed without `CAP_CHOWN`.
///
/// There is no world-writable mode. A non-root caller without the group cannot
/// connect, and the daemon never falls back to accepting everyone.
pub fn spawn_admin(
    generations: std::sync::Arc<daer_control::Generations>,
) -> Option<tokio::task::JoinHandle<()>> {
    let path = socket_path();
    let _ = std::fs::remove_file(&path);
    let listener = match std::os::unix::net::UnixListener::bind(&path) {
        Ok(listener) => listener,
        Err(error) => {
            daer_observe::warn!(
                daer_observe::EventCode::ElectionSocketFailed,
                path = %path.display(),
                %error,
                "could not bind the runtime election socket"
            );
            return None;
        }
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let gid = admin_gid();
        let mode = if gid.is_some() { 0o660 } else { 0o600 };
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode));
        if let Some(gid) = gid
            && let Err(error) = chown_gid(&path, gid)
        {
            daer_observe::warn!(
                daer_observe::EventCode::ElectionSocketFailed,
                path = %path.display(),
                %error,
                "could not chown the runtime election socket to its admin group; it remains root-only"
            );
        }
    }
    if listener.set_nonblocking(true).is_err() {
        return None;
    }
    Some(tokio::spawn(async move {
        let Ok(listener) = tokio::net::UnixListener::from_std(listener) else {
            return;
        };
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                continue;
            };
            let generations = std::sync::Arc::clone(&generations);
            tokio::spawn(async move {
                serve_one(stream, &generations).await;
            });
        }
    }))
}

async fn serve_one(mut stream: tokio::net::UnixStream, generations: &daer_control::Generations) {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let peer = stream.peer_cred().ok();
    let mut buffer = vec![0u8; 8192];
    let read = match stream.read(&mut buffer).await {
        Ok(read) => read,
        Err(_) => return,
    };
    let request: Request = match serde_json::from_slice(&buffer[..read]) {
        Ok(request) => request,
        Err(parse_error) => {
            let response = error(
                "invalid_request",
                format!("request is not valid JSON: {parse_error}"),
            );
            let _ = stream
                .write_all(
                    serde_json::to_string(&response)
                        .unwrap_or_default()
                        .as_bytes(),
                )
                .await;
            return;
        }
    };
    let response = match request.command.as_str() {
        "elect" => {
            let (Some(election), Some(node)) = (request.election, request.node) else {
                return write_response(
                    stream,
                    error("invalid_request", "elect requires election and node"),
                )
                .await;
            };
            let router = generations.current().router_arc();
            match router.elect(&election, &node) {
                Ok(()) => {
                    daer_observe::info!(
                        daer_observe::EventCode::ElectionPinned,
                        election = %election,
                        node = %node,
                        peer_uid = peer.map_or(0, |cred| cred.uid()),
                        peer_pid = peer.map_or(0, |cred| cred.pid().unwrap_or(0)),
                        generation = %generations.current().describe(),
                        persisted = true,
                        "election pinned"
                    );
                    ok(json!({"election": election, "node": node, "pinned": true}))
                }
                Err(message) => {
                    daer_observe::warn!(
                        daer_observe::EventCode::ElectionRejected,
                        election = %election,
                        node = %node,
                        %message,
                        peer_uid = peer.map_or(0, |cred| cred.uid()),
                        peer_pid = peer.map_or(0, |cred| cred.pid().unwrap_or(0)),
                        "election change rejected"
                    );
                    error("election_rejected", message)
                }
            }
        }
        "reset" => {
            let Some(election) = request.election else {
                return write_response(stream, error("invalid_request", "reset requires election"))
                    .await;
            };
            let router = generations.current().router_arc();
            match router.reset_election(&election) {
                Ok(()) => {
                    daer_observe::info!(
                        daer_observe::EventCode::ElectionReset,
                        election = %election,
                        peer_uid = peer.map_or(0, |cred| cred.uid()),
                        peer_pid = peer.map_or(0, |cred| cred.pid().unwrap_or(0)),
                        generation = %generations.current().describe(),
                        persisted = true,
                        "election reset"
                    );
                    ok(json!({"election": election, "reset": true}))
                }
                Err(message) => {
                    daer_observe::warn!(
                        daer_observe::EventCode::ElectionRejected,
                        election = %election,
                        %message,
                        "election reset rejected"
                    );
                    error("election_rejected", message)
                }
            }
        }
        "view" => {
            let view = request.view.unwrap_or_else(|| "elections".to_owned());
            let router = generations.current().router_arc();
            match view.as_str() {
                "nodes" => ok(json!({"nodes": router.nodes()})),
                "groups" => ok(json!({"groups": router.groups()})),
                "elections" => ok(json!({"elections": router.elections()})),
                other => error("unknown_view", format!("unknown view {other:?}")),
            }
        }
        other => error("unknown_command", format!("unknown command {other:?}")),
    };
    write_response(stream, response).await;
}

async fn write_response(mut stream: tokio::net::UnixStream, response: Response) {
    use tokio::io::AsyncWriteExt as _;
    let body = serde_json::to_vec(&response).unwrap_or_else(|_| b"{\"ok\":false}".to_vec());
    let _ = stream.write_all(&body).await;
}

fn admin_gid() -> Option<libc::gid_t> {
    // Non-root delegation is opt-in. No variable means root-only, not "try a group".
    let name = std::env::var("DAER_ADMIN_GROUP").ok()?;
    let name = CString::new(name).ok()?;
    // `getgrnam_r` is the reentrant form: the daemon is multi-threaded by the time the
    // admin socket is bound, and the non-`_r` call returns a pointer into a shared buffer.
    let mut buffer = vec![0u8; 4096];
    let mut group = std::mem::MaybeUninit::<libc::group>::zeroed();
    let mut result: *mut libc::group = std::ptr::null_mut();
    // SAFETY: all pointers are valid for the duration of the call; the buffer is writable
    // and the group storage is initialized by `zeroed`.
    let code = unsafe {
        libc::getgrnam_r(
            name.as_ptr(),
            group.as_mut_ptr(),
            buffer.as_mut_ptr().cast::<libc::c_char>(),
            buffer.len(),
            &mut result,
        )
    };
    if code == 0 && !result.is_null() {
        // SAFETY: `result` points at `group`, which `getgrnam_r` initialized.
        Some(unsafe { group.assume_init() }.gr_gid)
    } else {
        None
    }
}

fn chown_gid(path: &std::path::Path, gid: libc::gid_t) -> std::io::Result<()> {
    let path = CString::new(path.as_os_str().as_encoded_bytes())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "path has NUL"))?;
    // SAFETY: `path` is a valid C string; chown takes no other pointer.
    let result = unsafe { libc::chown(path.as_ptr(), 0, gid) };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// The public view returned by `status --nodes/--groups/--elections`.
#[derive(Debug, serde::Deserialize)]
pub struct ViewResponse {
    pub ok: bool,
    pub body: Option<Value>,
    pub error: Option<ViewError>,
}

#[derive(Debug, serde::Deserialize)]
pub struct ViewError {
    pub message: String,
}

async fn request(request: &Request) -> anyhow::Result<ViewResponse> {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let mut stream = tokio::net::UnixStream::connect(socket_path())
        .await
        .map_err(|error| {
            anyhow::anyhow!(
                "cannot connect to {}: {error}; is `daer run` running?",
                socket_path().display()
            )
        })?;
    let body = serde_json::to_vec(request)?;
    stream.write_all(&body).await?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await?;
    serde_json::from_slice(&response)
        .map_err(|error| anyhow::anyhow!("the admin socket returned invalid JSON: {error}"))
}

/// Queries one of the read-only views.
pub async fn query(view: &str) -> anyhow::Result<Value> {
    let response = request(&Request {
        command: "view".to_owned(),
        election: None,
        node: None,
        view: Some(view.to_owned()),
    })
    .await?;
    if response.ok {
        response
            .body
            .ok_or_else(|| anyhow::anyhow!("the admin socket returned no body"))
    } else {
        let error = response
            .error
            .map_or_else(|| "unknown error".to_owned(), |error| error.message);
        anyhow::bail!("{error}")
    }
}

/// Pins an election to a node.
pub async fn elect(election: &str, node: &str) -> anyhow::Result<Value> {
    let response = request(&Request {
        command: "elect".to_owned(),
        election: Some(election.to_owned()),
        node: Some(node.to_owned()),
        view: None,
    })
    .await?;
    if response.ok {
        response
            .body
            .ok_or_else(|| anyhow::anyhow!("the admin socket returned no body"))
    } else {
        let error = response
            .error
            .map_or_else(|| "unknown error".to_owned(), |error| error.message);
        anyhow::bail!("{error}")
    }
}

/// Clears an election's runtime override.
pub async fn reset(election: &str) -> anyhow::Result<Value> {
    let response = request(&Request {
        command: "reset".to_owned(),
        election: Some(election.to_owned()),
        node: None,
        view: None,
    })
    .await?;
    if response.ok {
        response
            .body
            .ok_or_else(|| anyhow::anyhow!("the admin socket returned no body"))
    } else {
        let error = response
            .error
            .map_or_else(|| "unknown error".to_owned(), |error| error.message);
        anyhow::bail!("{error}")
    }
}

/// Removes the socket on shutdown.
pub fn remove_socket() {
    let _ = std::fs::remove_file(socket_path());
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn temp(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "daer-control-{name}-{}-{}.sock",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ))
    }

    #[tokio::test]
    async fn elect_query_and_reset_round_trip() {
        let socket = temp("elect");
        let state = socket.with_extension("json");
        // SAFETY: this test is the only one in this binary that touches these variables.
        unsafe {
            std::env::set_var("DAER_ADMIN_SOCKET", &socket);
            std::env::set_var("DAER_ELECTION_STATE", &state);
            std::env::remove_var("DAER_ADMIN_GROUP");
        }
        let config = daer_config::toml_config::load_str(
            "schema = 6\n\
             [[node]]\nname = \"n1\"\ntype = \"socks5\"\nserver = \"127.0.0.1\"\nport = 1080\n\
             [[node]]\nname = \"n2\"\ntype = \"socks5\"\nserver = \"127.0.0.1\"\nport = 1081\n\
             [[group]]\nname = \"pool\"\n\
             [[election]]\nname = \"proxy\"\ngroup = \"pool\"\ntype = \"random\"\n\
             [routing]\ndefault = \"proxy\"\n",
        )
        .expect("config loads");
        let overrides = Arc::new(daer_control::ElectionOverrides::load(Some(state.clone())));
        let options = daer_control::RouterOptions::default().with_overrides(Arc::clone(&overrides));
        let generations =
            Arc::new(daer_control::Generations::new(&config, &options).expect("generation builds"));
        let task = spawn_admin(Arc::clone(&generations)).expect("admin socket binds");
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&socket)
                .expect("socket exists")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600, "the default admin socket is root-only");
        }

        let value = elect("proxy", "n2").await.expect("elects n2");
        assert_eq!(value["node"], "n2");
        assert_eq!(
            generations
                .current()
                .router()
                .node_identity("proxy")
                .unwrap()
                .node,
            "n2"
        );

        let view = query("elections").await.expect("queries elections");
        let election = view["elections"]
            .as_array()
            .and_then(|items| items.first())
            .expect("one election");
        assert_eq!(election["pinned"], "n2");

        let value = reset("proxy").await.expect("resets");
        assert_eq!(value["reset"], true);
        assert!(overrides.get("proxy").is_none());

        task.abort();
        let _ = task.await;
        let _ = std::fs::remove_file(&socket);
        let _ = std::fs::remove_file(&state);
        // SAFETY: same single-threaded test scope as the `set_var` calls above.
        unsafe {
            std::env::remove_var("DAER_ADMIN_SOCKET");
            std::env::remove_var("DAER_ELECTION_STATE");
        }
    }
}
