# Diagnostic Event Reference

This file is generated from `crates/daer-observe/events.toml` by `cargo xtask events`.
The **code** is the stable contract; the message is presentation. An event with a
`warn` or `error` severity always has a counter, a rate-limit group and a remediation.

Run `cargo xtask events --check` to fail on catalog drift.

| Code | Level | Message | Required fields | Counter | Rate | Remediation |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `daemon.build` | `info` | daemon build | `version`, `commit`, `dirty`, `built_at`, `rustc`, `target`, `netune`, `object_sha256` | — | — | — |
| `daemon.ready` | `info` | daemon ready | `run_id`, `generation`, `datapath`, `port`, `namespace`, `so_mark` | — | — | — |
| `daemon.interfaces_resolved` | `info` | interfaces resolved | `lan`, `wan` | — | — | — |
| `daemon.listening` | `info` | listening for redirected flows | `port`, `so_mark`, `namespace`, `generation` | — | — | — |
| `daemon.datapath_attached` | `info` | datapath attached | `port`, `namespace`, `device`, `peer`, `lan`, `wan`, `object`, `object_sha256`, `maps`, `programs`, `policy_hash` | — | — | — |
| `daemon.datapath_rebuilt` | `info` | generation rebuilt with the datapath's flow facts | `generation` | — | — | — |
| `daemon.datapath_rebuild_failed` | `warn` | could not rebuild the generation with the datapath's flow facts | `error` | `daemon.datapath_rebuild_failed` | `daemon.datapath_rebuild_failed` | mac/dscp/pname rules will not match until the generation rebuild succeeds; fix the reported error and reload. |
| `daemon.config_warning` | `warn` | configuration warning | `warning` | `daemon.config_warning` | `daemon.config_warning` | Run `daer check` and fix the reported configuration warning. |
| `daemon.dns_started` | `info` | dns server started | `plan`, `fake_ip` | — | — | — |
| `daemon.dns_not_started` | `info` | dns server not started | — | — | — | — |
| `daemon.dns_stopped_with_error` | `warn` | dns server stopped with an error | `error` | `daemon.dns_stopped_with_error` | `daemon.dns_stopped_with_error` | DNS-based routing and Fake-IP are unavailable; restart the daemon and inspect the resolver error. |
| `daemon.dns_task_failed` | `warn` | dns server task did not finish | `error` | `daemon.dns_task_failed` | `daemon.dns_task_failed` | The resolver task ended abnormally; restart the daemon and collect the incident bundle. |
| `daemon.udp_unavailable` | `warn` | the UDP relay is not running | `error`, `port` | `daemon.udp_unavailable` | `daemon.udp_unavailable` | TCP is unaffected; fix the datagram bind error and reload if UDP clients are expected. |
| `daemon.no_datapath` | `warn` | serving without the kernel datapath | — | `daemon.no_datapath` | `daemon.no_datapath` | Nothing is redirected into the transparent port; this mode is for development, not traffic. |
| `daemon.health_started` | `info` | health scheduling started | `interval` | — | — | — |
| `daemon.health_disabled` | `debug` | health probing not started | `probes`, `reason` | — | — | — |
| `daemon.waiting_route` | `info` | waiting for a default route | `disable_waiting_network` | — | — | — |
| `daemon.waiting_interfaces` | `info` | waiting for the interfaces to come up | `reason` | — | — | — |
| `daemon.wan_detected` | `info` | detected the WAN interface | `interface` | — | — | — |
| `daemon.status_socket_failed` | `debug` | could not bind the read-only status socket | `path`, `error` | — | — | — |
| `daemon.state_write_failed` | `debug` | could not write the runtime state snapshot | `path`, `error` | — | — | — |
| `daemon.shutdown` | `info` | shutdown complete | `drained`, `in_flight`, `accepted`, `rejected`, `failed`, `exhausted`, `panicked`, `datagram`, `dns` | — | — | — |
| `daemon.stopping` | `info` | stopped accepting; live flows keep relaying | `in_flight` | — | — | — |
| `daemon.sd_notify_disabled` | `debug` | systemd notifications are disabled | `error` | — | — | — |
| `daemon.sd_notify_failed` | `debug` | could not send a systemd notification | `error` | — | — | — |
| `dryrun.report` | `info` | dry-run report | `stage` | — | — | — |
| `dryrun.config_compiles` | `info` | configuration compiles | `generation`, `rules` | — | — | — |
| `dryrun.kernel_equivalent` | `info` | kernel policy is equivalent | `generation` | — | — | — |
| `dryrun.kernel_deferral` | `warn` | kernel policy is a deferral | `reasons` | `dryrun.kernel_deferral` | `dryrun.kernel_deferral` | Traffic is correct but the kernel fast path is not in effect; rewrite the named predicates or accept the userspace relay hop. |
| `dryrun.listen` | `info` | would listen for redirected flows | `port`, `so_mark`, `namespace`, `generation` | — | — | — |
| `dryrun.interfaces` | `info` | would attach to these interfaces | `lan`, `wan` | — | — | — |
| `dryrun.host_sysctl_missing` | `warn` | host sysctl prerequisite is not met | `error` | `dryrun.host_sysctl_missing` | `dryrun.host_sysctl_missing` | Run `daer check --dry-run` on the host that will serve traffic; a real run would refuse to start. |
| `dryrun.no_datapath` | `warn` | no datapath | — | `dryrun.no_datapath` | `dryrun.no_datapath` | Nothing is redirected into the transparent port; do not use this mode to serve traffic. |
| `dryrun.object_valid` | `info` | datapath object is valid | `object`, `maps`, `programs` | — | — | — |
| `dryrun.pair_state` | `info` | pair state | `device_present`, `peer_present`, `state` | — | — | — |
| `dryrun.capabilities_present` | `info` | capabilities present | — | — | — | — |
| `dryrun.privileged_skipped` | `warn` | the privileged phase would not run here | `reason` | `dryrun.privileged_skipped` | `dryrun.privileged_skipped` | Run the privileged gate on a host with CAP_BPF, CAP_NET_ADMIN, CAP_PERFMON and CAP_SYS_ADMIN. |
| `dryrun.complete` | `info` | dry-run complete | — | — | — | — |
| `generation.loaded` | `info` | configuration loaded | `generation`, `rules`, `groups`, `elections`, `nodes`, `build_ms`, `policy_hash` | — | — | — |
| `generation.reloaded` | `info` | configuration reloaded | `generation`, `previous`, `rules`, `groups`, `elections`, `nodes`, `routing_changed`, `build_ms`, `policy_hash`, `source` | — | — | — |
| `generation.startup_rejected` | `error` | configuration rejected; nothing is serving | `generation`, `error`, `error_code` | `generation.startup_rejected` | `generation.startup_rejected` | Run `daer check -c <config>` and fix the reported error; the daemon cannot serve without a generation. |
| `generation.reload_rejected` | `error` | configuration reload rejected; the running generation is unchanged | `generation`, `serving`, `error`, `error_code` | `generation.reload_rejected` | `generation.reload_rejected` | Run `daer check -c <config>`; the previous generation is still serving, so this is not an outage. |
| `generation.rule_warning` | `warn` | routing rule compiled with a warning | `warning` | `generation.rule_warning` | `generation.rule_warning` | Run `daer check --why` and fix the rule; a warning means the compiled rule may not match what was written. |
| `generation.node_unselectable` | `warn` | node protocol is not implemented by this build | `node`, `protocol`, `message` | `generation.node_unselectable` | `generation.node_unselectable` | Use a supported protocol for this node or remove it; an unknown protocol is never downgraded to direct. |
| `provider.refresh_skipped` | `error` | rule provider refresh skipped: the configuration does not load | `error` | `provider.refresh_skipped` | `provider.refresh_skipped` | Fix the configuration; the running generation is unchanged. |
| `provider.removed` | `debug` | rule provider no longer declared | `tag` | — | — | — |
| `provider.updated` | `info` | rule provider updated | `tag`, `bytes`, `sha256`, `generation` | — | — | — |
| `provider.unchanged` | `debug` | rule provider unchanged | `tag` | — | — | — |
| `provider.refresh_failed` | `warn` | rule provider refresh failed; keeping the running rule set | `tag`, `error`, `error_code` | `provider.refresh_failed` | `provider.refresh_failed` | Check the provider URL and network; the previous rule set remains active. |
| `provider.refresh_published` | `info` | rule provider refresh published a new generation | `tag`, `generation`, `elapsed_ms` | — | — | — |
| `provider.refresh_rejected` | `error` | refresh rejected; the running generation is unchanged | `error` | `provider.refresh_rejected` | `provider.refresh_rejected` | The refreshed rule set did not compile; fix it or roll back the provider. |
| `provider.cadence_reread_failed` | `warn` | could not re-read the provider cadence | `error` | `provider.cadence_reread_failed` | `provider.cadence_reread_failed` | The previous cadence is still in use; check the configuration file for a concurrent edit. |
| `provider.not_modified` | `debug` | rule provider not modified | `tag`, `status` | — | — | — |
| `provider.cache_fallback` | `warn` | rule provider fetch failed; loaded from cached DRB | `tag`, `error` | `provider.cache_fallback` | `provider.cache_fallback` | The rules are stale but serving; check the provider URL and network. |
| `election.probe_method_invalid` | `warn` | probe method is not GET or HEAD; falling back to HEAD | `method`, `error` | `election.probe_method_invalid` | `election.probe_method_invalid` | Use GET or HEAD for an election probe. |
| `election.probe_udp_name` | `debug` | probe udp-dns entry is a name; not resolved | `entries` | — | — | — |
| `subscription.link_rejected` | `warn` | unsupported subscription node link (skipped) | `scheme`, `node`, `error` | `subscription.link_rejected` | `subscription.link_rejected` | The link is not usable by this build; remove it or use a supported protocol. The link is redacted. |
| `flow.dns_mapping` | `debug` | flow resolved via dns mapping | `flow_id`, `generation`, `destination`, `domain` | — | — | — |
| `flow.sniffed` | `debug` | flow sniffed | `flow_id`, `generation`, `destination`, `sniffed` | — | — | — |
| `flow.not_sniffed` | `trace` | flow not sniffed | `flow_id`, `generation`, `destination`, `reason` | — | — | — |
| `flow.decided` | `debug` | flow decided | `flow_id`, `generation`, `source`, `destination`, `rule`, `outbound`, `mark`, `must`, `domain`, `decision_source`, `elapsed_us` | — | — | — |
| `flow.datagram_decided` | `debug` | datagram flow decided | `flow_id`, `generation`, `source`, `destination`, `rule`, `outbound`, `mark`, `must` | — | — | — |
| `flow.node_selected` | `trace` | node selected | `flow_id`, `election`, `node`, `protocol`, `kind`, `latency_us` | — | — | — |
| `flow.accepted` | `debug` | accepted redirected flow | `flow_id`, `source`, `destination`, `l4` | — | — | — |
| `flow.rejected` | `debug` | dropped a flow that was not redirected | `flow_id`, `reject`, `reason` | — | — | — |
| `flow.no_outbound` | `debug` | no outbound leg | `flow_id`, `destination`, `error` | — | — | — |
| `flow.closed` | `debug` | flow closed | `flow_id`, `destination`, `outcome`, `to_upstream`, `to_client`, `elapsed_ms` | — | — | — |
| `flow.relay_failed` | `warn` | relay failed | `flow_id`, `destination`, `error`, `error_code` | `flow.relay_failed` | `flow.relay_failed` | The client or origin closed abnormally; inspect the node and the bundle's flow record. |
| `flow.abnormal_end` | `warn` | flow task ended abnormally | `flow_id`, `generation`, `destination` | `flow.abnormal_end` | `flow.abnormal_end` | A flow task was cancelled or panicked; collect the incident bundle and inspect the last flow record. |
| `flow.accept_resource_exhausted` | `warn` | accept failed on a resource limit; backing off | `error` | `flow.accept_resource_exhausted` | `flow.accept_resource_exhausted` | Raise `LimitNOFILE` or reduce connection pressure; the loop backs off and keeps serving. |
| `flow.accept_stopped` | `info` | relay accept loop stopped | `accepted`, `rejected`, `failed` | — | — | — |
| `flow.dial_finished` | `debug` | dial finished | `flow_id`, `dial`, `node`, `authority`, `dns_us`, `tcp_us`, `tls_us`, `rtt_us` | — | — | — |
| `flow.dial_finished_without_timings` | `debug` | dial finished without timings | `flow_id`, `dial`, `node`, `authority` | — | — | — |
| `flow.dial_failed` | `warn` | flow dial failed | `flow_id`, `generation`, `destination`, `election`, `node`, `stage`, `error_code`, `elapsed_ms` | `flow.dial_failed` | `flow.dial_failed` | Check the selected node and the dial stage; run `daer probe node <node>`. |
| `flow.datagram_ingress_stopped` | `info` | datagram ingress stopped; live sessions keep replying | `in_flight` | — | — | — |
| `flow.datagram_reaped` | `debug` | reaped idle datagram sessions | `reaped` | — | — | — |
| `flow.datagram_ingress_failed` | `trace` | ingress datagram failed; continuing | `error` | — | — | — |
| `flow.datagram_rejected` | `debug` | dropped a datagram that was not redirected | `flow_id`, `reject`, `reason` | — | — | — |
| `flow.datagram_forward_failed` | `warn` | datagram forward failed | `flow_id`, `error` | `flow.datagram_forward_failed` | `flow.datagram_forward_failed` | The upstream leg failed; check the node and the UDP transport. |
| `flow.datagram_refused` | `warn` | datagram flow refused | `flow_id`, `destination`, `error`, `error_code` | `flow.datagram_refused` | `flow.datagram_refused` | The election has no electable datagram-capable node; check the node and probe settings. |
| `flow.datagram_session_failed` | `warn` | datagram session failed | `flow_id`, `destination`, `error` | `flow.datagram_session_failed` | `flow.datagram_session_failed` | The UDP session could not be opened; inspect the selected node. |
| `flow.datagram_session_closed` | `debug` | datagram session closed | `flow_id`, `destination`, `error` | — | — | — |
| `flow.datagram_reply_failed` | `warn` | datagram reply failed | `flow_id`, `destination`, `error` | `flow.datagram_reply_failed` | `flow.datagram_reply_failed` | The reply socket could not send to the client; check the ingress namespace and the reply socket mark. |
| `dns.request_routed` | `debug` | dns request routed | `query_id`, `peer`, `question`, `decision` | — | — | — |
| `dns.answer_routed` | `debug` | dns answer routed | `query_id`, `peer`, `question`, `upstream`, `action`, `elapsed_ms`, `rcode` | — | — | — |
| `dns.upstream_failed` | `warn` | dns upstream failed | `query_id`, `peer`, `question`, `upstream`, `transport`, `error`, `error_code`, `elapsed_ms` | `dns.upstream_failed` | `dns.upstream_failed` | Check the upstream address, transport and network; the query was answered with SERVFAIL. |
| `dns.failover_self` | `warn` | dns.response failover targets the same upstream; ignoring | `query_id`, `upstream` | `dns.failover_self` | `dns.failover_self` | Point the failover at a different upstream; a self-referential failover is ignored. |
| `dns.failover_failed` | `warn` | dns failover failed | `query_id`, `upstream`, `error` | `dns.failover_failed` | `dns.failover_failed` | The second upstream also failed; check both upstreams and the network. |
| `dns.cache_stored` | `trace` | dns answer cached | `query_id`, `ttl` | — | — | — |
| `dns.cache_skipped` | `trace` | dns answer not cached | `query_id`, `skipped` | — | — | — |
| `dns.cache_stale` | `debug` | dns stale answer served; a refresh is owed | `query_id`, `question`, `expired_for_ms` | — | — | — |
| `dns.family_filtered` | `trace` | dns: dropped the dispreferred address family from a mixed answer | `query_id` | — | — | — |
| `dns.udp_listening` | `info` | dns udp server listening | `address` | — | — | — |
| `dns.udp_stopping` | `info` | dns udp server stopping | — | — | — | — |
| `dns.tcp_listening` | `info` | dns tcp server listening | `address` | — | — | — |
| `dns.tcp_stopping` | `info` | dns tcp server stopping | — | — | — | — |
| `dns.transient_error` | `debug` | dns transient error | `query_id`, `peer`, `transport`, `phase`, `error` | — | — | — |
| `dns.malformed_query` | `debug` | dns malformed query | `query_id`, `peer`, `transport`, `bytes` | — | — | — |
| `dns.send_failed` | `warn` | dns send failed | `query_id`, `peer`, `transport`, `error` | `dns.send_failed` | `dns.send_failed` | The client did not receive its answer; check the listening socket and the reply path. |
| `dns.resolution_failed` | `warn` | dns resolution failed | `query_id`, `peer`, `transport`, `error`, `timeout` | `dns.resolution_failed` | `dns.resolution_failed` | The resolver could not answer; inspect the upstream event with the same query_id. |
| `dns.tcp_connection_ended` | `debug` | dns tcp connection ended | `peer`, `error` | — | — | — |
| `dns.asis_no_reply` | `trace` | asis: no reply | `query_id`, `peer`, `transport` | — | — | — |
| `health.probe_record_failed` | `warn` | probe result could not be recorded; this generation is stale | `election`, `node`, `error` | `health.probe_record_failed` | `health.probe_record_failed` | The health scheduler holds a stale router; reload the generation and restart the scheduler. |
| `health.node_alive` | `trace` | node alive | `probe_id`, `election`, `node`, `latency_ns` | — | — | — |
| `health.probe_failed` | `warn` | node probe failed | `probe_id`, `election`, `node`, `failure`, `consecutive_failures` | `health.probe_failed` | `health.probe_failed` | Run `daer probe node <node>`; the node is not selectable until a probe succeeds. |
| `health.node_unprobeable` | `debug` | node has no literal address; not probed | `election`, `node` | — | — | — |
| `health.scheduler_stopped` | `info` | health scheduler stopped | — | — | — | — |
| `health.probing_disabled` | `debug` | health probing disabled | `interval` | — | — | — |
| `datapath.policy_published` | `info` | datapath policy published | `generation`, `slot`, `entries`, `trie_entries`, `policy_hash` | — | — | — |
| `datapath.policy_deferred` | `warn` | datapath policy published as a deferral | `generation`, `slot`, `entries`, `reasons`, `policy_hash` | `datapath.policy_deferred` | `datapath.policy_deferred` | Traffic is correct but every flow is handed to userspace; rewrite the named predicates or accept the relay hop. |
| `datapath.republish_failed` | `error` | republishing kernel policy failed | `generation`, `error` | `datapath.republish_failed` | `datapath.republish_failed` | The kernel keeps the previous slot; inspect the object and `daer status` before the next reload. |
| `datapath.object_missing` | `error` | cannot reach the datapath object | `reason`, `path` | `datapath.object_missing` | `datapath.object_missing` | Run `cargo xtask ebpf` or install the packaged datapath object at the configured path. |
| `datapath.cleanup_failed` | `warn` | datapath cleanup failed | `error` | `datapath.cleanup_failed` | `datapath.cleanup_failed` | The ingress namespace is private; stopping the process releases it. Inspect the namespace with `nsenter --mount=/proc/<pid>/ns/mnt ip netns list` while the process lives. |
| `datapath.ipv6_unavailable` | `warn` | IPv6 datapath is unavailable; IPv4 continues | `component`, `error` | `datapath.ipv6_unavailable` | `datapath.ipv6_unavailable` | Enable IPv6 forwarding/routing on the host if IPv6 clients are expected; IPv4 is unaffected. |
| `datapath.sysctl_restore_failed` | `warn` | could not restore a host sysctl | `path`, `error` | `datapath.sysctl_restore_failed` | `datapath.sysctl_restore_failed` | The value is per-device and disappears with `daer0`; inspect `/proc/sys/net/ipv4/conf/daer0` while the device exists. |
| `datapath.peer_detach_failed` | `warn` | could not detach the peer ingress link | `error` | `datapath.peer_detach_failed` | `datapath.peer_detach_failed` | The link is fd-owned and detaches with the process. Inspect `bpftool link show`; no qdisc or persistent filter is created. |
| `datapath.telemetry_failed` | `warn` | datapath telemetry read failed | `error` | `datapath.telemetry_failed` | `datapath.telemetry_failed` | The counters or ring are no longer readable; collect the daemon log and inspect the loaded object before the next reload. |
| `datapath.stats` | `info` | datapath counters | `interval_ms`, `counters` | — | — | — |
| `datapath.event` | `warn` | datapath event | `event_type`, `counter`, `pid`, `pname`, `outbound`, `l4proto`, `sip`, `dip`, `sport`, `dport`, `monotonic_ns` | `datapath.event` | `datapath.event` | Inspect the named kernel event and counter; repeated overflow or rebind events indicate map or epoch pressure. |
| `netns.ipv6_unavailable` | `warn` | IPv6 ingress state is unavailable | `component`, `error` | `netns.ipv6_unavailable` | `netns.ipv6_unavailable` | Enable IPv6 on the host and in `daer0ns` if IPv6 clients are expected; IPv4 is unaffected. |
| `netns.cleanup_failed` | `warn` | could not remove the ingress namespace mount | `error` | `netns.cleanup_failed` | `netns.cleanup_failed` | The namespace mount is private to the daemon's mount namespace. Inspect it with `nsenter --mount=/proc/<pid>/ns/mnt ip netns list`. |
| `protocol.anytls_alert` | `warn` | anytls received alert from server | `alert` | `protocol.anytls_alert` | `protocol.anytls_alert` | The node rejected the session; check credentials and the node's policy. |
| `protocol.anytls_session_error` | `debug` | anytls session error | `phase`, `error` | — | — | — |
| `observe.ring_dropped` | `warn` | diagnostic ring dropped events | `dropped`, `capacity` | `observe.ring_dropped` | `observe.ring_dropped` | Increase `global.diagnostics.event-buffer` or reduce debug volume; the event stream is incomplete. |
| `incident.capture_failed` | `warn` | incident bundle could not be written | `trigger`, `error` | `incident.capture_failed` | `incident.capture_failed` | Check that /var/lib/daer/incidents or /run/daer is writable; the panic/signal itself is still reported on stderr. |
| `incident.capture` | `warn` | incident bundle captured | `incident_id`, `trigger`, `path`, `events`, `redaction` | `incident.capture` | `incident.capture` | Attach the bundle to the incident record; do not paste raw logs separately. |
| `election.pinned` | `info` | election pinned to a node | `election`, `node`, `previous`, `peer_uid`, `peer_pid`, `generation`, `persisted` | — | — | — |
| `election.reset` | `info` | election reset to its configured rule | `election`, `previous`, `peer_uid`, `peer_pid`, `generation`, `persisted` | — | — | — |
| `election.rejected` | `warn` | election change rejected | `election`, `node`, `error`, `peer_uid`, `peer_pid` | `election.rejected` | `election.rejected` | Run `daer status --elections` to inspect valid elections and candidates. |
| `election.state_rejected` | `warn` | election state file is not usable; starting without overrides | `path`, `schema`, `expected`, `error` | `election.state_rejected` | `election.state_rejected` | Inspect /var/lib/daer/elections.json; a corrupt state file is ignored, never fatal. |
| `election.state_write_failed` | `warn` | could not persist election state | `error` | `election.state_write_failed` | `election.state_write_failed` | Check that /var/lib/daer is writable and has free space; the running election may not survive a restart. |
| `election.override_pruned` | `warn` | election override no longer names a valid candidate | `election`, `node` | `election.override_pruned` | `election.override_pruned` | Run `daer status --elections`; the election now follows its configured rule. |
| `election.socket_failed` | `warn` | could not bind the runtime election admin socket | `path`, `error` | `election.socket_failed` | `election.socket_failed` | Check that /run/daer is writable and that the daemon user owns it; daer elect and the live status views need this socket. |

## How to read this table

- **Code** is what you filter, count, link from an incident, and test. It does not change
  when a message is reworded. A rename is a contract change and needs a new code.
- **Level** is the catalog's severity, not a call-site choice. `cargo xtask events --check`
  compares the macro used at the call site with this table.
- **Counter** is exact even when the log line is rate-limited. Volume comes from counters,
  never from counting sampled lines.
- **Remediation** is the operator's next action. It is not a restatement of the message.
