// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2022-2026, daer contributors
//
// Part of the datapath translation unit. See ADR-0024 for why the split is by
// map ownership and attach domain rather than by directory convention.

struct get_real_comm_ctx {
	char *arg_buf;
	u8 l;
};

static int __noinline get_real_comm_loop_cb(__u32 index, void *data)
{
	/*
	* For string like: /usr/lib/sddm/sddm-helper --socket /tmp/sddm-auth1
	* We extract "sddm-helper" from it.
	*/
	struct get_real_comm_ctx *ctx = (struct get_real_comm_ctx *)data;

	if (index >= MAX_ARG_LEN) // always false, just to make verifier happy
		return 1;
	if (unlikely(ctx->arg_buf[index] == '/'))
		ctx->l = index + 1;
	if (unlikely(ctx->arg_buf[index] == ' ' ||
		     ctx->arg_buf[index] == '\0')) {
		// Write to dst.
		ctx->arg_buf[index] = '\0';
		return 1;
	}
	return 0;
}

/// Parse command line arguments to get the real command name and tgid.
static __always_inline int get_pid_pname(struct pid_pname *pid_pname)
{
	int ret;

	// Populate tgid and timestamp first
	pid_pname->last_seen_ns = bpf_ktime_get_ns();
	pid_pname->pid = bpf_get_current_pid_tgid() >> 32;

	if (!PARAM.has_bpf_get_current_task) {
		if (bpf_get_current_comm(&pid_pname->pname, sizeof(pid_pname->pname)))
			pid_pname->pname[0] = '\0';
		return 0;
	}

	// Get pointer to args string.
	struct task_struct *task = (void *)bpf_get_current_task();
	char *args = (void *)BPF_CORE_READ(task, mm, arg_start);

	// Read args to buffer.
	char arg_buf[MAX_ARG_LEN]; // Allocate it out of ctx to pass CO-RE
	struct get_real_comm_ctx ctx = {};

	ctx.arg_buf = arg_buf;
	ret = bpf_core_read_user_str(arg_buf, MAX_ARG_LEN, args);
	if (unlikely(ret < 0)) {
		return ret;
	}

	// Find range of command name.
	ret = bpf_loop(MAX_ARG_LEN, get_real_comm_loop_cb, &ctx, 0);
	if (unlikely(ret < 0))
		return ret;

	u8 offset = ctx.l;

	for (u8 i = 0; i < TASK_COMM_LEN; i++) {
		if (offset + i < MAX_ARG_LEN && arg_buf[offset + i] != '\0') {
			pid_pname->pname[i] = arg_buf[offset + i];
		} else {
			pid_pname->pname[i] = '\0';
			break;
		}
	}

	return 0;
}

static __always_inline int _update_map_elem_by_cookie(const __u64 cookie)
{
	if (unlikely(!cookie)) {
		return -EINVAL;
	}
	struct pid_pname *existing = bpf_map_lookup_elem(&cookie_pid_map, &cookie);

	if (existing) {
		// Cookie to pid mapping already exists.
		existing->last_seen_ns = bpf_ktime_get_ns();
		return 0;
	}

	int ret;
	// Build value.
	struct pid_pname val = { 0 };

	ret = get_pid_pname(&val);
	if (ret)
		return ret;

	// Update map.
	ret = bpf_map_update_elem(&cookie_pid_map, &cookie, &val, BPF_ANY);
	if (unlikely(ret))
		return ret;

	return 0;
}

static __always_inline int update_map_elem_by_cookie(const __u64 cookie)
{
	int ret;

	ret = _update_map_elem_by_cookie(cookie);
	if (ret) {
		// Fallback to only write pid to avoid loop due to packets sent by daer.
		struct pid_pname val = { 0 };

		val.last_seen_ns = bpf_ktime_get_ns();
		val.pid = bpf_get_current_pid_tgid() >> 32;
		bpf_map_update_elem(&cookie_pid_map, &cookie, &val, BPF_ANY);
		return ret;
	}
	return 0;
}

// Create cookie to pid, pname mapping.
SEC("cgroup/sock_create")
int tproxy_wan_cg_sock_create(struct bpf_sock *sk)
{
	update_map_elem_by_cookie(bpf_get_socket_cookie(sk));
	return 1;
}

// Remove cookie to pid, pname mapping.
SEC("cgroup/sock_release")
int tproxy_wan_cg_sock_release(struct bpf_sock *sk)
{
	__u64 cookie = bpf_get_socket_cookie(sk);

	if (unlikely(!cookie)) {
		return 1;
	}
	bpf_map_delete_elem(&cookie_pid_map, &cookie);
	return 1;
}

SEC("cgroup/connect4")
int tproxy_wan_cg_connect4(struct bpf_sock_addr *ctx)
{
	update_map_elem_by_cookie(bpf_get_socket_cookie(ctx));
	return 1;
}

SEC("cgroup/connect6")
int tproxy_wan_cg_connect6(struct bpf_sock_addr *ctx)
{
	update_map_elem_by_cookie(bpf_get_socket_cookie(ctx));
	return 1;
}

SEC("cgroup/sendmsg4")
int tproxy_wan_cg_sendmsg4(struct bpf_sock_addr *ctx)
{
	update_map_elem_by_cookie(bpf_get_socket_cookie(ctx));
	return 1;
}

SEC("cgroup/sendmsg6")
int tproxy_wan_cg_sendmsg6(struct bpf_sock_addr *ctx)
{
	update_map_elem_by_cookie(bpf_get_socket_cookie(ctx));
	return 1;
}


