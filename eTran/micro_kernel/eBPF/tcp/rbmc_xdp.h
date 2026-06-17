/*
 * rbmc_xdp.h — BMC-style cache serving fused into eTran's XDP TCP layer.
 *
 * System (4) of the 4-way comparison: serve Redis GET cache-hits directly in
 * XDP, while eTran owns the TCP connection state (seq/ack in bpf_tcp_conn).
 *
 * Cache core is rbmc's (struct rbmc_cache_entry, FNV-1a, RESP parse, direct-
 * mapped slot = hash & mask, learn-on-miss, epoch/version consistency) — kept
 * byte-identical to code/redis_bmc/rbmc_common.h so systems (2) and (4) share
 * the same cache. The MiddleCache-style seq/ack translation of the XDP-BMC
 * reference (erb_kern.c) is dropped: eTran assigns seq from c->tx_next_seq.
 *
 * v1 (this file): lossless-correct, single-outstanding (pipeline=1). The served
 * reply advances ONLY c->tx_next_seq (NOT tx_sent / tx_next_pos). PRECONDITIONS
 * enforced by the caller (xdp_sock_prog): (a) the request fully ACKs prior lib
 * TX (ack_seq==tx_next_seq && tx_pending==0) — so after tcp_rx_process tx_sent==0
 * and the client's reply-ACK yields tx_bump==0 in tcp_valid_rxack, never
 * disturbing the lib's unack_tx_addrs/txb_sent; (b) the GET exactly fills its
 * segment (no pipelining) — else punt the whole segment to Redis. Non-quiescent
 * or pipelined requests fall through to Redis (correct, just unaccelerated).
 * Closed-world invalidation: bare SET invalidates its slot; any other mutating
 * command bumps the global epoch (flush). Loss-correct re-serve is deferred to v2.
 *
 * verifier discipline (mirrors rbmc): hash & mask (2^n), constant-bound loops
 * with per-access data_end guards, barrier_var + runtime clamp before/after
 * adjust_tail, constant-size reply copy.
 */
#ifndef _RBMC_XDP_H
#define _RBMC_XDP_H

/* ── cache layout (verbatim from code/redis_bmc/rbmc_common.h) ───────────── */
#define RBMC_MAX_KEY_LEN   100
#define RBMC_MAX_VAL_LEN   1000
#define RBMC_MAX_REPLY_LEN (1 + 4 + 2 + RBMC_MAX_VAL_LEN + 2) /* "$<vlen>\r\n"+v+"\r\n" */
#define RBMC_REPLY_BUF_LEN 1016 /* 8B aligned + slack */

#define RBMC_DEFAULT_PORT          6379
/* cache entries = direct-mapped slots; hit ratio is controlled by this size
 * relative to the keyspace (learn-on-miss fills it). Must be a power of two.
 * Override per hit-ratio-sweep point: -DRBMC_CACHE_ENTRIES_DEFAULT=N */
#ifndef RBMC_CACHE_ENTRIES_DEFAULT
#define RBMC_CACHE_ENTRIES_DEFAULT 65536 /* 2^16 default (>10k keyspace → ~100% hit) */
#endif

#define FNV_OFFSET_BASIS_32 2166136261u
#define FNV_PRIME_32        16777619u

/* payload offset for an established-state data segment: ETH+IP+TCP+[NOP NOP TS] */
#define RBMC_PAYLOAD_OFF (sizeof(struct ethhdr) + sizeof(struct iphdr) + \
			  sizeof(struct tcphdr) + TS_OPT_SIZE)

struct rbmc_cache_entry {
	struct bpf_spin_lock lock;
	__u32 epoch;
	__u32 version;
	__u32 valid;
	__u32 hash;
	__u32 key_len;
	__u32 reply_len;
	char key[RBMC_MAX_KEY_LEN];
	char reply[RBMC_REPLY_BUF_LEN] __attribute__((aligned(8)));
};

/* per-connection GET-miss pending state (learn-on-miss). keyed by eTran flow. */
struct rbmc_pending {
	__u32 valid;
	__u32 hash;
	__u32 klen;
	__u32 slot_version;
	__u32 epoch;
	char key[RBMC_MAX_KEY_LEN];
};

/* lock-free scratch (helpers forbidden inside the cache spin lock) */
struct rbmc_xdp_scratch {
	__u32 len;
	char key[RBMC_MAX_KEY_LEN];
	char reply[RBMC_REPLY_BUF_LEN] __attribute__((aligned(8)));
};

struct rbmc_xdp_stats {
	__u64 get_recv, set_recv, hit, miss, fill, fill_raced, invalidation;
	__u64 oversize, grow_fail, serve_xdp;
};

#ifndef READ_ONCE
#define READ_ONCE(x)     (*(volatile typeof(x) *)&(x))
#endif
#ifndef WRITE_ONCE
#define WRITE_ONCE(x, v) (*(volatile typeof(x) *)&(x) = (v))
#endif
#ifndef barrier_var
#define barrier_var(var) asm volatile("" : "=r"(var) : "0"(var))
#endif

const volatile __u16 rbmc_xdp_port      = RBMC_DEFAULT_PORT;
const volatile __u32 rbmc_xdp_mask      = RBMC_CACHE_ENTRIES_DEFAULT - 1;

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, RBMC_CACHE_ENTRIES_DEFAULT); /* loader overrides */
	__type(key, __u32);
	__type(value, struct rbmc_cache_entry);
} rbmc_cache SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} rbmc_epoch SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_TCP_FLOWS);
	__type(key, struct ebpf_flow_tuple);
	__type(value, struct rbmc_pending);
} rbmc_pending_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct rbmc_xdp_scratch);
} rbmc_xdp_scratch_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct rbmc_xdp_stats);
} rbmc_xdp_stats_map SEC(".maps");

static __always_inline struct rbmc_xdp_stats *rbmc_xdp_stats(void)
{
	__u32 z = 0;
	return bpf_map_lookup_elem(&rbmc_xdp_stats_map, &z);
}
#define RBMC_STAT(st, f) do { if (st) (st)->f++; } while (0)

static __always_inline __u32 rbmc_xdp_epoch_get(void)
{
	__u32 z = 0, *e = bpf_map_lookup_elem(&rbmc_epoch, &z);
	return e ? READ_ONCE(*e) : 0;
}

/* closed-world global invalidation: bump on any command that could mutate a
 * cached key but can't be localized to one slot (non-bare GET/SET, unparseable
 * SET key). Mirrors rbmc's rbmc_epoch_bump. */
static __always_inline void rbmc_xdp_epoch_bump(struct rbmc_xdp_stats *st)
{
	__u32 z = 0, *e = bpf_map_lookup_elem(&rbmc_epoch, &z);
	if (e)
		__sync_fetch_and_add(e, 1);
	(void)st;
}

static __always_inline int rbmc_lc(char c)
{
	return (c >= 'A' && c <= 'Z') ? (c | 0x20) : c;
}

#define RBMC_CMD_UNKNOWN 0
#define RBMC_CMD_GET     1
#define RBMC_CMD_SET     2

/* GET=*2\r\n$3\r\nGET\r\n... / SET=*3\r\n$3\r\nSET\r\n... ; fixed 13B prefix */
static __always_inline int rbmc_parse_prefix(char *p, void *data_end)
{
	if (p + 13 > (char *)data_end)
		return RBMC_CMD_UNKNOWN;
	if (p[0] != '*' || p[2] != '\r' || p[3] != '\n')
		return RBMC_CMD_UNKNOWN;
	if (p[4] != '$' || p[5] != '3' || p[6] != '\r' || p[7] != '\n')
		return RBMC_CMD_UNKNOWN;
	if (p[11] != '\r' || p[12] != '\n')
		return RBMC_CMD_UNKNOWN;
	{
		int a = rbmc_lc(p[8]), b = rbmc_lc(p[9]), c = rbmc_lc(p[10]);
		if (p[1] == '2' && a == 'g' && b == 'e' && c == 't')
			return RBMC_CMD_GET;
		if (p[1] == '3' && a == 's' && b == 'e' && c == 't')
			return RBMC_CMD_SET;
	}
	return RBMC_CMD_UNKNOWN;
}

#define RBMC_LEN_MAX (16u << 20)

/* parse "$<digits>\r\n" at p[off]; *val=number, *next=offset after "\r\n" */
static __always_inline int rbmc_parse_bulk_len(char *p, void *data_end, int off,
					       __u32 *val, int *next)
{
	__u32 n = 0;
	int got = 0, i;

	if (p + off + 1 > (char *)data_end || p[off] != '$')
		return -1;
	i = off + 1;
#pragma clang loop unroll(disable)
	for (int d = 0; d < 8; d++, i++) {
		char c;
		if (p + i + 1 > (char *)data_end)
			return -1;
		c = p[i];
		if (c == '\r')
			break;
		if (c < '0' || c > '9')
			return -1;
		n = n * 10 + (__u32)(c - '0');
		if (n > RBMC_LEN_MAX)
			return -1;
		got = 1;
	}
	if (!got)
		return -1;
	{
		char *q = p + i;
		if (q + 2 > (char *)data_end)
			return -1;
		if (q[0] != '\r' || q[1] != '\n')
			return -1;
	}
	*val = n;
	*next = i + 2;
	return 0;
}

/* read key bytes from the packet, copy to sc->key, FNV-1a hash. caller bounds
 * 1<=klen<=RBMC_MAX_KEY_LEN. p=payload start, key_off relative to p. */
static __always_inline int rbmc_hash_key(char *p, void *data_end, int key_off,
					 __u32 klen, struct rbmc_xdp_scratch *sc,
					 __u32 *hash_out)
{
	__u32 h = FNV_OFFSET_BASIS_32;
	__u32 n = klen;
	int j;

	barrier_var(n);
	if (n < 1)
		n = 1;
	if (n > RBMC_MAX_KEY_LEN)
		n = RBMC_MAX_KEY_LEN;
#pragma clang loop unroll(disable)
	for (j = 0; j < RBMC_MAX_KEY_LEN && j < (int)n; j++) {
		char c;
		if (p + key_off + j + 1 > (char *)data_end)
			return -1;
		c = p[key_off + j];
		h ^= (__u8)c;
		h *= FNV_PRIME_32;
		sc->key[j] = c;
	}
	*hash_out = h;
	return 0;
}

#define RBMC_SERVE_NONE 0 /* not a cache hit — fall through to normal eTran RX */
#define RBMC_SERVE_HIT  1 /* reply in scratch, build + XDP_TX after rx consumed */

/*
 * Classify + (for GET) look up the cache. Reads the request payload directly
 * from the XDP frame (data..data_end). On a GET hit, copies the precomputed
 * reply into the per-CPU scratch and returns RBMC_SERVE_HIT (caller builds the
 * reply once tcp_rx_process has consumed the request). On GET-miss, records
 * pending state for learn-on-miss. On SET, invalidates the slot. Always returns
 * RBMC_SERVE_NONE except for a clean single-request GET hit.
 */
static __always_inline int rbmc_xdp_classify(void *data, void *data_end,
					     struct ebpf_flow_tuple *key,
					     __u32 *out_reply_len)
{
	struct rbmc_xdp_stats *st = rbmc_xdp_stats();
	struct rbmc_xdp_scratch *sc;
	struct rbmc_cache_entry *entry;
	struct rbmc_pending pend = {};
	char *p = (char *)data + RBMC_PAYLOAD_OFF;
	int seg_payload = (int)((char *)data_end - p); /* this segment's payload bytes */
	__u32 z = 0, hash, slot, ge, ver, klen;
	int cmd, key_off, req_end, j, hit = 0;

	if (seg_payload < 1)
		return RBMC_SERVE_NONE;

	cmd = rbmc_parse_prefix(p, data_end);
	if (cmd == RBMC_CMD_UNKNOWN) {
		/* closed-world: a valid RESP array that is not bare GET/SET
		 * (DEL/EXPIRE/FLUSHALL/RENAME/MSET/SET-with-opts/...) may mutate a
		 * cached key but can't be localized → global invalidate. */
		if (p + 1 <= (char *)data_end && p[0] == '*')
			rbmc_xdp_epoch_bump(st);
		return RBMC_SERVE_NONE;
	}
	if (rbmc_parse_bulk_len(p, data_end, 13, &klen, &key_off) < 0 ||
	    klen < 1 || klen > RBMC_MAX_KEY_LEN) {
		if (cmd == RBMC_CMD_SET)
			rbmc_xdp_epoch_bump(st); /* unlocalizable SET → flush */
		return RBMC_SERVE_NONE;
	}

	sc = bpf_map_lookup_elem(&rbmc_xdp_scratch_map, &z);
	if (!sc)
		return RBMC_SERVE_NONE;
	if (rbmc_hash_key(p, data_end, key_off, klen, sc, &hash) < 0) {
		if (cmd == RBMC_CMD_SET)
			rbmc_xdp_epoch_bump(st);
		return RBMC_SERVE_NONE;
	}

	slot = hash & rbmc_xdp_mask;
	entry = bpf_map_lookup_elem(&rbmc_cache, &slot);
	if (!entry)
		return RBMC_SERVE_NONE;

	if (cmd == RBMC_CMD_SET) {
		RBMC_STAT(st, set_recv);
		bpf_spin_lock(&entry->lock);
		entry->valid = 0;
		entry->version++;
		bpf_spin_unlock(&entry->lock);
		RBMC_STAT(st, invalidation);
		return RBMC_SERVE_NONE; /* SET passes through to Redis */
	}

	/* GET. Require the request to exactly fill the segment (single-outstanding
	 * / pipeline=1). Pipelined or coalesced segments → punt whole segment to
	 * Redis (no serve, no cache) so tcp_rx_process consuming the full payload
	 * never strands an unanswered 2nd request. */
	req_end = key_off + (int)klen + 2;
	if (req_end != seg_payload)
		return RBMC_SERVE_NONE;

	RBMC_STAT(st, get_recv);
	ge = rbmc_xdp_epoch_get();
	bpf_spin_lock(&entry->lock);
	ver = entry->version;
	if (entry->valid && entry->epoch == ge && entry->hash == hash &&
	    entry->key_len == klen) {
		int eq = 1;
#pragma clang loop unroll(disable)
		for (j = 0; j < RBMC_MAX_KEY_LEN && j < (int)klen; j++) {
			if (entry->key[j] != sc->key[j]) {
				eq = 0;
				break;
			}
		}
		if (eq) {
#pragma clang loop unroll(disable)
			for (j = 0; j + 8 <= RBMC_REPLY_BUF_LEN; j += 8)
				*(__u64 *)(sc->reply + j) = *(__u64 *)(entry->reply + j);
			sc->len = entry->reply_len;
			hit = 1;
		}
	}
	bpf_spin_unlock(&entry->lock);

	if (hit) {
		RBMC_STAT(st, hit);
		*out_reply_len = sc->len;
		return RBMC_SERVE_HIT;
	}

	/* miss → record pending for learn-on-miss, then fall through to Redis */
	RBMC_STAT(st, miss);
	pend.valid = 1;
	pend.hash = hash;
	pend.klen = klen;
	pend.slot_version = ver;
	pend.epoch = ge;
#pragma clang loop unroll(disable)
	for (j = 0; j < RBMC_MAX_KEY_LEN; j++)
		pend.key[j] = sc->key[j];
	bpf_map_update_elem(&rbmc_pending_map, key, &pend, BPF_ANY);
	return RBMC_SERVE_NONE;
}

/*
 * Is there room in this CPU's ACK/SERVE queue to enqueue a serve? Reserve a
 * 2-slot margin (one for the serve, one for the deferred prev_conn ACK that
 * xdp_gen flushes at batch end). If the queue is near full (heavy multi-conn
 * batches), the caller declines the hit and lets Redis answer — the cache still
 * holds the value for next time, so a request is never stranded.
 */
static __always_inline int rbmc_xdp_ack_room(__u32 cpu)
{
	__u32 used;
	if (cpu >= MAX_CPU)
		return 0;
	used = (ack_prod[cpu] - ack_cons[cpu]) & (NAPI_BATCH_SIZE - 1);
	return used + 2 < NAPI_BATCH_SIZE;
}

/*
 * Enqueue a GET cache-hit SERVE into this CPU's ACK queue for the XDP_GEN path.
 * Called from xdp_sock_prog AFTER tcp_rx_process has validated+consumed the
 * request (rx_next_seq advanced). The reply bytes are in the per-CPU scratch;
 * we snapshot them (and seq/ack) into the queue entry NOW, because xdp_gen runs
 * deferred (batch end) and the cache slot may be mutated by a later packet in
 * the same batch. v1 seq-coherence: advance ONLY c->tx_next_seq — the served
 * bytes stay invisible to the lib's tx accounting (unack_tx_addrs/tx_sent), so
 * the client's reply-ACK yields tx_bump==0 and never desyncs it.
 *
 * Only enqueues — the caller (xdp_sock_prog) REDIRECTS the consumed request
 * frame to the lib (which triggers run_xdp_gen this batch and recycles the
 * frame). The reply is emitted by xdp_gen_prog from a FRESH page-pool frame that
 * the kernel auto-recycles after TX — no UMEM/fill-ring leak (the bug the old
 * in-place XDP_TX serve hit: that frame was never returned to the pool). Return
 * value is unused by the caller.
 */
static __always_inline int rbmc_xdp_enqueue_serve(struct bpf_tcp_conn *c,
						  __u32 cpu, __u32 reply_len)
{
	struct rbmc_xdp_stats *st = rbmc_xdp_stats();
	struct rbmc_xdp_scratch *sc;
	struct bpf_tcp_ack *ack;
	__u32 z = 0, prod, now, wnd, rlen = reply_len;
	int j;

	if (cpu >= MAX_CPU)
		return XDP_DROP;
	sc = bpf_map_lookup_elem(&rbmc_xdp_scratch_map, &z);
	if (!sc)
		return XDP_DROP;

	barrier_var(rlen);
	if (rlen < 4)
		rlen = 4;
	if (rlen > RBMC_MAX_REPLY_LEN)
		rlen = RBMC_MAX_REPLY_LEN;

	prod = ack_prod[cpu];
	ack = bpf_map_lookup_elem(&bpf_tcp_ack_map, &prod);
	if (!ack)
		return XDP_DROP;

	/* compute the timestamp and all map lookups BEFORE the spin lock — helpers
	 * are forbidden while holding a bpf_spin_lock. */
	now = (__u32)bpf_ktime_get_ns();

	TCP_LOCK(c);
	ack->local_ip = c->local_ip;
	ack->remote_ip = c->remote_ip;
	ack->local_port = c->local_port;
	ack->remote_port = c->remote_port;
	ack->seq = c->tx_next_seq;   /* reply data starts at the current snd_nxt */
	ack->ack = c->rx_next_seq;   /* acks the GET request just consumed */
	wnd = c->rx_avail >> TCP_WND_SCALE;
	ack->rxwnd = wnd > 0xFFFF ? 0xFFFF : wnd;
	ack->ts_val = now;
	ack->ts_ecr = c->tx_next_ts;
	c->tx_next_ts = 0;
	c->tx_next_seq += rlen;      /* v1: advance ONLY tx_next_seq */
	TCP_UNLOCK(c);

	ack->ecn_flags = 0;
	ack->reply_len = (__u16)rlen;
	/* constant-size copy (verifier-friendly); gen emits only reply_len bytes */
#pragma clang loop unroll(disable)
	for (j = 0; j + 8 <= RBMC_REPLY_BUF_LEN; j += 8)
		*(__u64 *)(ack->reply + j) = *(__u64 *)(sc->reply + j);
	ack->type = BPF_TCP_ACK_TYPE_SERVE;

	/* publish to the consumer (xdp_gen) only after the entry is fully built */
	ack_prod[cpu] = (prod + 1) & (NAPI_BATCH_SIZE - 1);

	RBMC_STAT(st, serve_xdp);
	return XDP_DROP;
}

#ifdef RBMC_XDP_V2
/*
 * v2 IN-PLACE serve (BMC-style, the cleanest path): rewrite the request frame
 * itself into the reply and XDP_TX it — zero userspace touch, single frame, no
 * deferral. Called from xdp_sock_prog ONLY when the served GET does not ACK any
 * lib TX (tx_bump==0); a GET that acks a prior +OK falls back to the v1
 * enqueue_serve+redirect path (which forwards the ack to the lib). Reply bytes
 * are in the per-CPU scratch (from classify, same packet).
 *
 * REQUIRES the v2 kernel patch (mlx5 RX-path XDP_TX → recycle the frame to the
 * fill ring on TX completion). WITHOUT that patch this LEAKS the UMEM frame
 * (eTran's cq-drain is gated on `outstanding`, which pure GET-hits never bump)
 * — that leak is exactly why v1 routes through XDP_GEN instead. Do NOT run a
 * -DRBMC_XDP_V2 build on an unpatched kernel.
 */
static __always_inline int rbmc_xdp_build_reply_inplace(struct xdp_md *ctx,
							struct bpf_tcp_conn *c,
							__u32 reply_len)
{
	struct rbmc_xdp_stats *st = rbmc_xdp_stats();
	struct rbmc_xdp_scratch *sc;
	void *data, *data_end;
	struct ethhdr *eth;
	struct iphdr *iph;
	struct tcphdr *tcph;
	__u32 z = 0, rlen = reply_len;
	int cur, target, dlen, j;
	__u64 ts;

	sc = bpf_map_lookup_elem(&rbmc_xdp_scratch_map, &z);
	if (!sc)
		return XDP_DROP;

	barrier_var(rlen);
	if (rlen < 4)
		rlen = 4;
	if (rlen > RBMC_MAX_REPLY_LEN)
		rlen = RBMC_MAX_REPLY_LEN;

	cur = (int)(ctx->data_end - ctx->data);
	target = (int)RBMC_PAYLOAD_OFF + (int)rlen;
	dlen = target - cur;
	if (bpf_xdp_adjust_tail(ctx, dlen)) {
		RBMC_STAT(st, grow_fail);
		return XDP_DROP;
	}

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;
	eth = (struct ethhdr *)data;
	if ((void *)(eth + 1) > data_end)
		return XDP_DROP;
	iph = (struct iphdr *)(eth + 1);
	if ((void *)(iph + 1) > data_end)
		return XDP_DROP;
	tcph = (struct tcphdr *)(iph + 1);
	{
		struct tcp_timestamp_opt *ts_opt =
			(struct tcp_timestamp_opt *)((__u8 *)(tcph + 1) + 2);
		if ((void *)(ts_opt + 1) > data_end)
			return XDP_DROP;
	}

	/* swap addresses/ports to reflect the response (server -> client) */
	iph->saddr = bpf_htonl(c->local_ip);
	iph->daddr = bpf_htonl(c->remote_ip);
	tcph->source = bpf_htons(c->local_port);
	tcph->dest = bpf_htons(c->remote_port);

	{
		char *pl = (char *)data + RBMC_PAYLOAD_OFF;
		barrier_var(rlen);
		if (rlen < 4)
			rlen = 4;
		if (rlen > RBMC_MAX_REPLY_LEN)
			rlen = RBMC_MAX_REPLY_LEN;
		if (pl + rlen > (char *)data_end)
			return XDP_DROP;
#pragma clang loop unroll(disable)
		for (j = 0; j < RBMC_REPLY_BUF_LEN && j < (int)rlen &&
			    pl + j + 1 <= (char *)data_end; j++)
			pl[j] = sc->reply[j];
	}

	ts = bpf_ktime_get_ns();

	/* eTran owns seq. v1 seq-coherence: advance ONLY tx_next_seq (this path
	 * runs only when tx_bump==0, so the lib's tx accounting is undisturbed). */
	TCP_LOCK(c);
	fill_tcp_hdr(iph, tcph, c, ts, data_end, TCP_FLAG_ACK | TCP_FLAG_PSH);
	fill_ip_hdr(iph, rlen, c->ecn_enable);
	c->tx_next_seq += rlen;
	TCP_UNLOCK(c);

	eth->h_proto = bpf_htons(ETH_P_IP);
	__builtin_memcpy(eth->h_dest, c->remote_mac, ETH_ALEN);
	__builtin_memcpy(eth->h_source, c->local_mac, ETH_ALEN);

	RBMC_STAT(st, serve_xdp);
	return XDP_TX;   /* kernel patch recycles this frame to the fill ring */
}
#endif /* RBMC_XDP_V2 */

/*
 * learn-on-miss: snoop a Redis-over-eTran GET response on the egress path and
 * populate the cache for the pending miss recorded on ingress. Called from
 * xdp_egress_prog BEFORE tcp_tx_process (payload present, headers not yet
 * stamped). payload_len = response bytes in this (single) frame. Mirrors rbmc's
 * sk_msg fill (version-race check, oversize/coalesced guards, epoch stamp).
 */
static __always_inline void rbmc_xdp_fill(struct xdp_md *ctx, void *data,
					  void *data_end,
					  struct ebpf_flow_tuple *key,
					  __u32 payload_len)
{
	struct rbmc_xdp_stats *st = rbmc_xdp_stats();
	struct rbmc_pending *pend;
	struct rbmc_xdp_scratch *sc;
	struct rbmc_cache_entry *entry;
	char *p = (char *)data + RBMC_PAYLOAD_OFF;
	__u32 z = 0, n, slot, total_u, cplen;
	int val_off, j;

	pend = bpf_map_lookup_elem(&rbmc_pending_map, key);
	if (!pend || !READ_ONCE(pend->valid))
		return;

	/* GET response must be "$<n>\r\n<value>\r\n"; nil ($-1)/+OK/-ERR not cached */
	if (p + 1 > (char *)data_end) {
		WRITE_ONCE(pend->valid, 0);
		return;
	}
	if (p[0] != '$') {
		WRITE_ONCE(pend->valid, 0);
		return;
	}
	if (rbmc_parse_bulk_len(p, data_end, 0, &n, &val_off) < 0) {
		WRITE_ONCE(pend->valid, 0);
		return;
	}
	total_u = (__u32)val_off + n + 2;
	if (total_u != payload_len) { /* coalesced/split — don't cache */
		WRITE_ONCE(pend->valid, 0);
		return;
	}
	if (n > RBMC_MAX_VAL_LEN) {
		RBMC_STAT(st, oversize);
		WRITE_ONCE(pend->valid, 0);
		return;
	}

	sc = bpf_map_lookup_elem(&rbmc_xdp_scratch_map, &z);
	if (!sc) {
		WRITE_ONCE(pend->valid, 0);
		return;
	}

	/* copy reply (wire bytes) into scratch via ONE helper (bpf_xdp_load_bytes)
	 * — a per-byte loop with data_end guards blows the egress verifier budget.
	 * copy key from pending (both outside the entry lock — no helpers in it). */
	cplen = total_u;
	barrier_var(cplen);
	if (cplen < 4)
		cplen = 4;
	if (cplen > RBMC_MAX_REPLY_LEN)
		cplen = RBMC_MAX_REPLY_LEN;
	if (bpf_xdp_load_bytes(ctx, RBMC_PAYLOAD_OFF, sc->reply, cplen)) {
		WRITE_ONCE(pend->valid, 0);
		return;
	}
#pragma clang loop unroll(disable)
	for (j = 0; j < RBMC_MAX_KEY_LEN; j++)
		sc->key[j] = pend->key[j];

	/* snapshot pending scalars before taking the entry lock (rbmc parity) */
	__u32 phash = pend->hash, pklen = pend->klen;
	__u32 pver = pend->slot_version, pepoch = pend->epoch;

	slot = phash & rbmc_xdp_mask;
	entry = bpf_map_lookup_elem(&rbmc_cache, &slot);
	if (entry) {
		bpf_spin_lock(&entry->lock);
		if (entry->version == pver) { /* no SET raced since the miss */
			entry->valid = 1;
			entry->epoch = pepoch;
			entry->hash = phash;
			entry->key_len = pklen;
			entry->reply_len = cplen;
#pragma clang loop unroll(disable)
			for (j = 0; j < RBMC_MAX_KEY_LEN; j++)
				entry->key[j] = sc->key[j];
#pragma clang loop unroll(disable)
			for (j = 0; j + 8 <= RBMC_REPLY_BUF_LEN; j += 8)
				*(__u64 *)(entry->reply + j) = *(__u64 *)(sc->reply + j);
			RBMC_STAT(st, fill);
		} else {
			RBMC_STAT(st, fill_raced);
		}
		bpf_spin_unlock(&entry->lock);
	}
	WRITE_ONCE(pend->valid, 0);
}

#endif /* _RBMC_XDP_H */
