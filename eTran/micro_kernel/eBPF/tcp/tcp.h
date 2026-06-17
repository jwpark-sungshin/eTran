#pragma once
#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
#include <linux/types.h>

#include <intf/intf_ebpf.h>

#include "../ebpf_utils.h"
#include "../ebpf_queue.h"
#include "eTran_defs.h"
#include "pacing.h"

#define TCP_ACK_HEADER_CUTOFF (int)(XDP_GEN_PKT_SIZE - sizeof(struct ethhdr) - sizeof(struct iphdr) - sizeof(struct tcphdr) - TS_OPT_SIZE)

#if defined(XDP_DEBUG) || defined(XDP_EGRESS_DEBUG) || defined(XDP_GEN_DEBUG)
#define TCP_LOCK(c)
#define TCP_UNLOCK(c)
#else
// #define TCP_LOCK(c)
// #define TCP_UNLOCK(c)
#define TCP_LOCK(c) bpf_spin_lock(&c->lock)
#define TCP_UNLOCK(c) bpf_spin_unlock(&c->lock)
#endif

#define NULL_CONN __UINT32_MAX__
// we use cc_idx to identify each connection
// TODO: much more configurable
SEC(".data.prev_conn")
__u32 prev_conn[MAX_CPU] = {__UINT32_MAX__, __UINT32_MAX__, __UINT32_MAX__, __UINT32_MAX__, __UINT32_MAX__,
                            __UINT32_MAX__, __UINT32_MAX__, __UINT32_MAX__, __UINT32_MAX__, __UINT32_MAX__,
                            __UINT32_MAX__, __UINT32_MAX__, __UINT32_MAX__, __UINT32_MAX__, __UINT32_MAX__,
                            __UINT32_MAX__, __UINT32_MAX__, __UINT32_MAX__, __UINT32_MAX__, __UINT32_MAX__,
};
__u32 prev_conn_li[MAX_CPU];
__u16 prev_conn_lp[MAX_CPU];
__u32 prev_conn_ri[MAX_CPU];
__u16 prev_conn_rp[MAX_CPU];
__u8 prev_conn_ece[MAX_CPU];

/**
 * default value in linux kernel:
 * /proc/sys/net/core/rmem_default 212992
 * /proc/sys/net/core/wmem_default 212992
 */

// FIXME 
#define TCP_WND_SCALE 3

#define TCP_OPT_END_OF_OPTIONS 0
#define TCP_OPT_NO_OP 1
#define TCP_OPT_MSS 2
#define TCP_OPT_TIMESTAMP 8

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct ebpf_flow_tuple);
    __type(value, struct bpf_tcp_conn);
    __uint(max_entries, MAX_TCP_FLOWS);
} bpf_tcp_conn_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct bpf_cc);
    __uint(max_entries, MAX_TCP_FLOWS);
    __uint(map_flags, BPF_F_MMAPABLE);
} bpf_cc_map SEC(".maps");

// ACK
// emulate a per-cpu SCSP queue with BPF_MAP_TYPE_PERCPU_ARRAY
#ifdef RBMC_XDP
/* rbmc-xdp serves GET cache hits through the XDP_GEN path: a SERVE entry is a
 * normal ACK plus a snapshot of the reply bytes. Snapshotting at enqueue time
 * (RX) keeps the served value correct even if a later packet in the same NAPI
 * batch mutates the cache slot before xdp_gen runs (deferred). Must match
 * rbmc_xdp.h's RBMC_REPLY_BUF_LEN (guarded there too). */
#ifndef RBMC_REPLY_BUF_LEN
#define RBMC_REPLY_BUF_LEN 1016
#endif
#define BPF_TCP_ACK_TYPE_ACK   0
#define BPF_TCP_ACK_TYPE_SERVE 1
#endif
struct bpf_tcp_ack {
    __u32 local_ip;
    __u32 remote_ip;
    __u16 local_port;
    __u16 remote_port;

    __u32 seq; // tx_next_seq
    __u32 ack; // rx_next_seq
    __u32 rxwnd; // rx_avail

    __u32 ts_val; // now
    __u32 ts_ecr; // tx_next_ts

    __u8 ecn_flags;
#ifdef RBMC_XDP
    __u8 type;        /* BPF_TCP_ACK_TYPE_{ACK,SERVE} */
    __u16 reply_len;  /* SERVE: response payload bytes following the TCP header */
    char reply[RBMC_REPLY_BUF_LEN] __attribute__((aligned(8)));
#endif
};

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, NAPI_BATCH_SIZE);
  __type(key, __u32);
  __type(value, struct bpf_tcp_ack);
} bpf_tcp_ack_map SEC(".maps");

SEC(".bss.ack_prod")
__u32 ack_prod[MAX_CPU];
SEC(".bss.ack_cons")
__u32 ack_cons[MAX_CPU];

#ifdef RBMC_XDP_V2
/* v2: per-CPU one-shot flag — tcp_rx_process sets it on a cache hit to tell
 * xdp_sock_prog whether to serve IN-PLACE (1, frame→reply XDP_TX, zero lib
 * touch) or fall back to the v1 enqueue_serve+redirect path (0, when the hit
 * acks prior lib TX). Same-CPU, same-packet → no race. */
SEC(".bss.serve_inplace")
__u8 serve_inplace[MAX_CPU];
#endif

SEC(".bss.tx_cached_ts")
__u64 tx_cached_ts[MAX_CPU];

SEC(".bss.rx_cached_ts")
__u64 rx_cached_ts[MAX_CPU];

static __always_inline int ackqueue_empty(void)
{
    __u32 cpu = bpf_get_smp_processor_id();
    if (unlikely(cpu >= MAX_CPU)) {
        xdp_gen_log_panic("cpu >= MAX_CPU");
        return 1;
    }
    return ack_prod[cpu] == ack_cons[cpu];
}

static __always_inline struct bpf_tcp_ack *dequeue_ack(void)
{
    __u32 cpu = bpf_get_smp_processor_id();
    if (unlikely(cpu >= MAX_CPU)) {
        xdp_gen_log_panic("cpu >= MAX_CPU");
        return NULL;
    }

    struct bpf_tcp_ack *ack;

    if (unlikely(ack_prod[cpu] == ack_cons[cpu])) {
        return NULL;
    }

    __u32 cons = ack_cons[cpu];

    ack = bpf_map_lookup_elem(&bpf_tcp_ack_map, &cons);

    ack_cons[cpu] = (ack_cons[cpu] + 1) & (NAPI_BATCH_SIZE - 1);

    return ack;
}

/**
 * @brief This function is called when:
 *        1) xdp_gen is triggered, which indicates that current NAPI batch is finished
 *        2) the connection whose pkt are processed is different from the previous one
 */
static __always_inline int enqueue_prev_ack(__u32 cpu)
{
    struct ebpf_flow_tuple key;
    int ece = 0;

    __u32 prod = ack_prod[cpu];
    __u32 cons = ack_cons[cpu];

    // check if ack queue is full
    if (cons == ((prod + 1) & (NAPI_BATCH_SIZE - 1))) {
        return -1;
    }

    __u32 now = bpf_ktime_get_ns();

    struct bpf_tcp_ack *ack = bpf_map_lookup_elem(&bpf_tcp_ack_map, &prod);
    if (!ack) {
        return -1;
    }

    ece = prev_conn_ece[cpu];

    key.local_ip = prev_conn_li[cpu];
    key.remote_ip = prev_conn_ri[cpu];
    key.local_port = prev_conn_lp[cpu];
    key.remote_port = prev_conn_rp[cpu];
    
    struct bpf_tcp_conn *c = bpf_map_lookup_elem(&bpf_tcp_conn_map, &key);
    if (!c) {
        return -1;
    }

    TCP_LOCK(c);
    ack->local_ip = c->local_ip;
    ack->remote_ip = c->remote_ip;
    ack->local_port = c->local_port;
    ack->remote_port = c->remote_port;

    ack->seq = c->tx_next_seq;
    ack->ack = c->rx_next_seq;

    ack->rxwnd = min(c->rx_avail >> TCP_WND_SCALE, 0xFFFF);
    
    ack->ts_val = now;
    ack->ts_ecr = c->tx_next_ts;
    c->tx_next_ts = 0;

    TCP_UNLOCK(c);

    ack->ecn_flags = ece ? 1 : 0;
#ifdef RBMC_XDP
    ack->type = BPF_TCP_ACK_TYPE_ACK;
#endif

    ack_prod[cpu] = (prod + 1) & (NAPI_BATCH_SIZE - 1);

    return 0;
}

static __always_inline int enqueue_ack(struct bpf_tcp_conn *c, struct bpf_tcp_ack *ack, __u32 cpu, __u32 now, bool ece)
{
    ack->local_ip = c->local_ip;
    ack->remote_ip = c->remote_ip;
    ack->local_port = c->local_port;
    ack->remote_port = c->remote_port;

    ack->seq = c->tx_next_seq;
    ack->ack = c->rx_next_seq;

    ack->rxwnd = min(c->rx_avail >> TCP_WND_SCALE, 0xFFFF);
    
    ack->ts_val = now;
    ack->ts_ecr = c->tx_next_ts;
    c->tx_next_ts = 0;

    ack->ecn_flags = ece ? 1 : 0;
#ifdef RBMC_XDP
    ack->type = BPF_TCP_ACK_TYPE_ACK;
#endif

    ack_prod[cpu] = (ack_prod[cpu] + 1) & (NAPI_BATCH_SIZE - 1);

    return 0;
}

static __always_inline __u32 xsk_budget_avail(const struct bpf_tcp_conn *c)
{
    return c->rx_remote_avail;
}

static __always_inline __u32 tcp_txavail(const struct bpf_tcp_conn *c)
{
    /* flow control window */
    return c->rx_remote_avail - c->tx_sent;
}

static __always_inline void set_tcp_flag(struct tcphdr *tcph, __u16 len, __u16 flags)
{
    tcph->res1 = 0;
    tcph->doff = len;
    tcph->fin = (flags & TCP_FLAG_FIN) ? 1 : 0;
    tcph->syn = (flags & TCP_FLAG_SYN) ? 1 : 0;
    tcph->rst = (flags & TCP_FLAG_RST) ? 1 : 0;
    tcph->psh = (flags & TCP_FLAG_PSH) ? 1 : 0;
    tcph->ack = (flags & TCP_FLAG_ACK) ? 1 : 0;
    tcph->urg = (flags & TCP_FLAG_URG) ? 1 : 0;
    tcph->ece = (flags & TCP_FLAG_ECE) ? 1 : 0;
    tcph->cwr = (flags & TCP_FLAG_CWR) ? 1 : 0;
}

// Fill IP header except for addresses
static __always_inline void fill_ip_hdr(struct iphdr *iph, __u32 payload_len, bool ece)
{
    /* fill ip header */
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = ece ? IPTOS_ECN_ECT0 : 0;
    iph->tot_len = bpf_htons(sizeof(struct iphdr) + sizeof(struct tcphdr) + TS_OPT_SIZE + payload_len);
    iph->id = bpf_htons(0);
    iph->frag_off = 0;
    iph->ttl = 0xff;
    iph->protocol = IPPROTO_TCP;

    __u64 csum = 0;
    ipv4_csum_inline(iph, &csum);
    iph->check = csum;
}

// Fill TCP header excpet for ports
static __always_inline void fill_tcp_hdr(struct iphdr *iph, struct tcphdr *tcph, struct bpf_tcp_conn *c, __u32 tgt_ts, void *data_end, __u16 flags)
{
    __u32 tx_seq = c->tx_next_seq;
    __u32 rx_wnd = c->rx_avail;
    __u32 ack_seq = c->rx_next_seq;
    __u32 ts_ecr = c->tx_next_ts;
    /* HookShift: standard option layout [NOP][NOP][TS kind=8 len=10] so kernel
     * TCP peers accept the segment. The old layout wrote the TS option at
     * tcph+1 with kind=TCPI_OPT_TIMESTAMPS (=1, a tcp_info bitmask, i.e. NOP)
     * and length=2 — garbage to a standard parser (latent in eTran<->eTran,
     * which never parses option kinds). */
    __u8 *opt = (__u8 *)(tcph + 1);
    struct tcp_timestamp_opt *ts_opt = (struct tcp_timestamp_opt *)(opt + 2);
    if ((void *)(ts_opt + 1) > data_end) {
        return;
    }
    __u16 len = 5 + TS_OPT_SIZE / 4;
    /* fill tcp header */
    tcph->seq = bpf_htonl(tx_seq);
    tcph->ack_seq = bpf_htonl(ack_seq);

    set_tcp_flag(tcph, len, flags);

    opt[0] = 1; /* TCPOPT_NOP */
    opt[1] = 1; /* TCPOPT_NOP */
    ts_opt->kind = 8;    /* TCPOPT_TIMESTAMP */
    ts_opt->length = 10; /* TCPOLEN_TIMESTAMP */
    ts_opt->ts_val = bpf_htonl(tgt_ts);
    ts_opt->ts_ecr = bpf_htonl(ts_ecr);

    /* HookShift: shift before byte-swapping (the old order swapped first and
     * shifted the big-endian value); clamp to 16 bits. */
    {
        __u32 wnd16 = rx_wnd >> TCP_WND_SCALE;
        tcph->window = bpf_htons(wnd16 > 0xFFFF ? 0xFFFF : wnd16);
    }
    tcph->urg_ptr = 0;

    /* HookShift: csum left to NIC L3/L4 offload (mlx5 cs_flags on XDP TX,
     * see etran-on-6.6.142 kernel patch); kernel peers validate checksums. */
    tcph->check = 0;
}

static __always_inline __u64 cc_get_desired_tx_ts(struct bpf_cc *cc, __u64 ref_ts, __u32 payload_len)
{
    // TODO: improve precision
    __u64 ns_delta = (__u64)1000000000 * payload_len / cc->rate;
    // __u64 ns_delta = (__u64)1000000000 * payload_len / 3125000000; // 25Gbps
    // __u64 ns_delta = (__u64)1000000000 * payload_len / 2500000000; // 20Gbps
    // __u64 ns_delta = (__u64)1000000000 * payload_len / 1250000000; // 10Gbps
    // __u64 ns_delta = (__u64)1000000000 * payload_len / 500000000; // 4Gbps
    // __u64 ns_delta = (__u64)1000000000 * payload_len / 250000000; // 2Gbps
    // __u64 ns_delta = (__u64)1000000000 * payload_len / 100000000; // 800Mbps
    // __u64 ns_delta = (__u64)1000000000 * payload_len / 25000000; // 200Mbps
    
    __u64 desired_tx_ts = cc->prev_desired_tx_ts + ns_delta;

    desired_tx_ts = max(ref_ts, desired_tx_ts);

    cc->prev_desired_tx_ts = desired_tx_ts;

    return desired_tx_ts;
} 

static __always_inline __u32 fast_retransmit(struct bpf_tcp_conn *c, struct bpf_cc *cc)
{
    __u32 go_back_bytes = c->tx_sent;
    __u32 x;

    /* reset flow state as if we never transmitted those segments */
    c->rx_dupack_cnt = 0;

    c->tx_next_seq -= go_back_bytes;
    if (c->tx_next_pos >= go_back_bytes) {
        c->tx_next_pos -= go_back_bytes;
    } else {
        x = go_back_bytes - c->tx_next_pos;
        c->tx_next_pos = c->tx_buf_size - x;
    }

    c->tx_pending = 0;
    c->rx_remote_avail += go_back_bytes;

    c->tx_sent = 0;
    cc->txp = 0;

    /* cut rate by half if first drop in control interval */
    if (cc->cnt_tx_drops == 0) {
        cc->rate >>= 1;
    }

    cc->cnt_tx_drops++;

    return c->tx_next_pos;
}

// Caller must hold bpf_spin_lock
static __always_inline int tcp_tx_process(struct iphdr *iph, struct tcphdr *tcph, struct bpf_tcp_conn *c, struct meta_info *data_meta, void *data_end)
{
    __u32 cpu = bpf_get_smp_processor_id();
    if (unlikely(cpu >= MAX_CPU))
        return XDP_DROP;
    __u32 rx_bump = data_meta->tx.rx_bump;
    __u32 payload_len = data_meta->tx.plen;
    __u32 tx_pending = data_meta->tx.tx_pending;
    __u32 tx_pos = data_meta->tx.tx_pos;
    
    __u64 ref_ts = 0;
    // optimization for timestamp
    if (!has_kick[cpu])
        ref_ts = bpf_ktime_get_ns();
    else
        ref_ts = tx_cached_ts[cpu];

    bool wnd_upd = false;

    struct bpf_cc *cc = bpf_map_lookup_elem(&bpf_cc_map, &c->cc_idx);
    if (unlikely(!cc)) {
        xdp_log_panic("cc is NULL, BUG!!!");
        return XDP_DROP;
    }

    TCP_LOCK(c);

    /* Timeout packet from slowpath, process it first */
    if (unlikely(data_meta->tx.flag & FLAG_TO)) {
        if (!c->tx_sent) {
            TCP_UNLOCK(c);
            xdp_egress_log("Timeout but no data to retransmit");
            return XDP_DROP;
        }
        data_meta->rx.go_back_pos = fast_retransmit(c, cc);
        // prepare to redirect to userspace
        data_meta->rx.qid = POISON_32;
        data_meta->rx.conn = c->opaque_connection;
        data_meta->rx.rx_pos = POISON_32;
        data_meta->rx.poff = POISON_16;
        data_meta->rx.plen = POISON_16;
        data_meta->rx.xsk_budget_avail = xsk_budget_avail(c);
        data_meta->rx.go_back_pos |= RECOVERY_MASK;
        data_meta->rx.ooo_bump = POISON_32;
        TCP_UNLOCK(c);
        // bpf_printk("Timeout triggers fast retransmission");
        return XDP_PASS; // redirect to userspace
    }

    /* update receving buffer space */
    if (rx_bump) {
        // if ((c->rx_avail >> TCP_WND_SCALE) == 0 && c->tx_avail == 0)
        if (c->tx_pending == 0)
            wnd_upd = true;
        c->rx_avail += rx_bump;
        xdp_egress_log("Rxwnd is updated from %u to %u", min((c->rx_avail - rx_bump) >> TCP_WND_SCALE, 0xFFFF), c->rx_avail);
    }

    /* Pure sync packet from userspace, drop or send a extra window update */
    if (unlikely(data_meta->tx.flag & FLAG_SYNC)) {
        xdp_egress_log("pure ctrl signal");
        if (wnd_upd) {
            /* receive buffer freed up from empty, need to send out a window update, if
             * we're not sending anyways. */
            fill_tcp_hdr(iph, tcph, c, ref_ts, data_end, TCP_FLAG_ACK);
            fill_ip_hdr(iph, 0, false);
            TCP_UNLOCK(c);
            xdp_egress_log("Rxwnd is updated from empty to %u, send extra ack", min(c->rx_avail >> TCP_WND_SCALE, 0xFFFF));
            return XDP_TX;
        }
        TCP_UNLOCK(c);
        return XDP_DROP;
    }

    // this is probably caused by fast retransmission as we reset the c->tx_next_pos
    // but there are pending packets in the queue, simply drop them
    if (unlikely(tx_pos != c->tx_next_pos)) {
        TCP_UNLOCK(c);
        xdp_egress_log("tx_pos(%u) != c->tx_next_pos(%u)", tx_pos, c->tx_next_pos);
        // bpf_printk("tx_pos(%u) != c->tx_next_pos(%u)", tx_pos, c->tx_next_pos);
        return XDP_DROP;
    }

    if (tx_pending)
        c->tx_pending += tx_pending;

    __u32 avail = tcp_txavail(c);

    if (unlikely(avail < payload_len)) {
        // FIXME
        // bpf_printk("c->rx_remote_avail(%u), c->tx_sent(%u), c->tx_avail(%u), payload_len(%u)", 
        //     c->rx_remote_avail, c->tx_sent, c->tx_avail, payload_len);
        // bpf_printk("avail(%u) < payload_len(%u)", avail, payload_len);
    }

    __u64 desired_tx_ts = cc_get_desired_tx_ts(cc, ref_ts, payload_len);

    /* HookShift: data segments must carry ACK (kernel peers discard
     * established-state segments without it; eTran's own RX never checked). */
    fill_tcp_hdr(iph, tcph, c, desired_tx_ts, data_end, TCP_FLAG_ACK | TCP_FLAG_PSH);

    fill_ip_hdr(iph, payload_len, c->ecn_enable);

    c->tx_next_seq += payload_len;
    c->tx_next_pos += payload_len;
    if (c->tx_next_pos >= c->tx_buf_size)
        c->tx_next_pos -= c->tx_buf_size;
    c->tx_sent += payload_len;
    cc->txp = c->tx_sent > 0;
    c->tx_pending -= payload_len;

    // /*** NO CC ***/
    // TCP_UNLOCK(c);
    // // xdp_egress_log("Always bypass rate limiter");
    // return XDP_TX;
    
    #ifdef BYPASS_RL
    if (cc->rate >= LINK_BANDWIDTH && !nr_pkts_in_tw[cpu]) {
        // eRPC recommends to bypass rate limiter
        goto bypass_rl;
    }
    #endif

    #ifdef BYPASS_RL
    if ((!nr_pkts_in_tw[cpu] || c->tx_sent == payload_len) && desired_tx_ts <= ref_ts) {
        goto bypass_rl;
    }
    #endif

    TCP_UNLOCK(c);

    // bpf_printk("cc->rate(%lu)", cc->rate);

    __u32 key = cpu;
    struct timing_wheel *tw_map = bpf_map_lookup_elem(&tw_outer_map, &key);
    if (unlikely(!tw_map)) {
        log_panic("tw_map is NULL");
        return XDP_DROP;
    }

    __u32 idx = tw_insert(cpu, desired_tx_ts);
    if (unlikely(idx == POISON_32)) {
        log_panic("idx == POISON_32");
        return XDP_DROP;
    }
    // bpf_printk("TW idx(%u), tx_ts(%lu), (%u)", idx, desired_tx_ts, cc->rate);

    return bpf_redirect_map(tw_map, idx, 0);

#ifdef BYPASS_RL
bypass_rl:
    TCP_UNLOCK(c);
    xdp_egress_log("bypass rate limiter");
    return XDP_TX;
#endif
}

/**
 * @brief Check if the received ACK is valid
 */
static __always_inline int tcp_valid_rxack(struct bpf_tcp_conn *c, __u32 ack_seq, __u32 *bump)
{
    __u32 exp_ack_first = c->tx_next_seq - c->tx_sent;
    __u32 exp_ack_last = c->tx_next_seq;

    // allow receving ack that we haven't sent yet, this is probably caused by retransmission
    exp_ack_last += c->tx_pending;

    if (exp_ack_first <= exp_ack_last) {
        if (ack_seq < exp_ack_first || ack_seq > exp_ack_last)
            return -1;

        // 0-----exp_ack_first-----ack_seq-----exp_ack_last-----__UINT32_MAX__
        *bump = ack_seq - exp_ack_first;
    } else {
        if (exp_ack_first > ack_seq && ack_seq > exp_ack_last)
            return -1;
        // 0-----exp_ack_first-----------------exp_ack_first--ack_seq---__UINT32_MAX__
        // 0--ack_seq---exp_ack_first-----------------exp_ack_first-----__UINT32_MAX__
        *bump = ack_seq - exp_ack_first;
    }

    xdp_log("exp_ack_first(%u), exp_ack_last(%u), ack_seq(%u), *bump(%u)", exp_ack_first, exp_ack_last, ack_seq, *bump);

    return 0;
}

/**
 * @brief Given a range [start, end), check if a sequence number is in the range,
 *        considering the wrap-around case. excluding indicates whether the seq is exclusive.
 */
static __always_inline bool seq_in_range(__u32 seq, __u32 start, __u32 end, bool excluding)
{
    if (start <= end) {
        return excluding ? (seq > start && seq <= end) : (seq >= start && seq < end);
    } else {
        return excluding ? (seq > start || seq <= end) : (seq >= start || seq < end);
    }
}

/**
 * @brief out-of-order version of tcp_valid_rxseq()
 *        as long as the pkt seq range has overlap with the receive buffer range,
 *        we consider it as a valid pkt
 */
static __always_inline int tcp_valid_rxseq_ooo(struct bpf_tcp_conn *c, __u32 seq, __u32 payload_len, __u32 *trim_start, __u32 *trim_end)
{
    __u32 exp_seq_first = c->rx_next_seq;
    __u32 exp_seq_last = c->rx_next_seq + c->rx_avail;

    __u32 pkt_seq_first = seq;
    __u32 pkt_seq_last = seq + payload_len;

    xdp_log("exp_seq_first(%u), exp_seq_last(%u), pkt_seq_first(%u), pkt_seq_last(%u)", exp_seq_first, exp_seq_last, pkt_seq_first, pkt_seq_last);

    bool valid = seq_in_range(pkt_seq_first, exp_seq_first, exp_seq_last, false) ||
                 seq_in_range(pkt_seq_last, exp_seq_first, exp_seq_last, true) ||
                 seq_in_range(exp_seq_first, pkt_seq_first, pkt_seq_last, false) ||
                 seq_in_range(exp_seq_last, pkt_seq_first, pkt_seq_last, true);
    
    if (!valid) {
        return -1;
    }

    if (seq_in_range(pkt_seq_first, exp_seq_first, exp_seq_last, false)) {
        *trim_start = 0;
    } else {
        *trim_start = exp_seq_first - pkt_seq_first;
    }

    if (seq_in_range(pkt_seq_last, exp_seq_first, exp_seq_last, true)) {
        *trim_end = 0;
    } else {
        *trim_end = pkt_seq_last - exp_seq_last;
    }

    xdp_log("*trim_start(%u), *trim_end(%u)", *trim_start, *trim_end);

    return 0;
}

/**
 * @brief Check if the received SEQ is valid
 */
static __always_inline int tcp_valid_rxseq(struct bpf_tcp_conn *c, __u32 seq, __u32 payload_len, __u32 *trim_start, __u32 *trim_end)
{
    __u32 exp_seq_first = c->rx_next_seq;
    __u32 exp_seq_last = c->rx_next_seq + c->rx_avail;

    __u32 pkt_seq_first = seq;
    __u32 pkt_seq_last = seq + payload_len;

    xdp_log("exp_seq_first(%u), exp_seq_last(%u), pkt_seq_first(%u), pkt_seq_last(%u)", exp_seq_first, exp_seq_last, pkt_seq_first, pkt_seq_last);

    if (exp_seq_first <= exp_seq_last && pkt_seq_first <= pkt_seq_last) {
        /* neither packet interval nor receive buffer split */

        /* packet ends before start of receive buffer */
        if (pkt_seq_last < exp_seq_first) return -1;

        /* packet starts after beginning of receive buffer */
        if (pkt_seq_first > exp_seq_first) return -1;

        *trim_start = exp_seq_first - pkt_seq_first;
        *trim_end = (pkt_seq_last > exp_seq_last) ? pkt_seq_last - exp_seq_last : 0; 
    } else if (pkt_seq_first <= pkt_seq_last && exp_seq_first > exp_seq_last) {
        /* packet interval not split, but receive buffer split */
        
        /* packet ends before start of receive buffer */
        if (pkt_seq_first >= exp_seq_last && pkt_seq_last < exp_seq_first) return -1;

        /* packet starts after beginning of receive buffer */
        if (pkt_seq_first > exp_seq_first || pkt_seq_first < exp_seq_last) return -1;

        *trim_start = exp_seq_first - pkt_seq_first;
        *trim_end = 0;
    } else if (pkt_seq_first > pkt_seq_last && exp_seq_first <= exp_seq_last) {
        /* packet interval split, receive buffer not split */

        /* packet ends before start of receive buffer */
        // TAS is wrong, this condition should be removed
        // if (pkt_seq_last < exp_seq_first) return -1;

        /* packet starts after beginning of receive buffer */
        if (pkt_seq_first > exp_seq_first) return -1;

        *trim_start = exp_seq_first - pkt_seq_first;
        *trim_end = (pkt_seq_last > exp_seq_last ? pkt_seq_last - exp_seq_last : 0);
    } else {
        /* both intervals split
        * Note this means that there is at least some overlap. */

        /* packet starts after beginning of receive buffer */
        if (pkt_seq_first > exp_seq_first) return -1;

        *trim_start = exp_seq_first - pkt_seq_first;
        *trim_end = (pkt_seq_last > exp_seq_last ? pkt_seq_last - exp_seq_last : 0);
    }

    return 0;
}

static __always_inline int tcp_rx_process(struct tcphdr *tcph, struct bpf_tcp_conn *c, __u32 pkt_len, struct meta_info *data_meta, bool ece, __u32 cpu, bool cache_hit)
{
    bool trigger_ack = false;
    __u32 go_back_pos = 0;
    __u32 payload_off = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr) + TS_OPT_SIZE;
    __u32 payload_len = pkt_len - payload_off;
    __u32 seq = bpf_ntohl(tcph->seq);
    __u32 ack_seq = bpf_ntohl(tcph->ack_seq);
    /* HookShift: standard [NOP][NOP][TS] layout — the TS option sits 2 NOPs
     * past the TCP header (kernel peers always emit this layout; our TX now
     * matches it too). Bounds were checked by the caller at the same offset. */
    struct tcp_timestamp_opt *ts_opt = (struct tcp_timestamp_opt *)((__u8 *)(tcph + 1) + 2);
    __u32 ts_val = bpf_ntohl(ts_opt->ts_val);
    __u32 ts_ecr = bpf_ntohl(ts_opt->ts_ecr);

    __u32 rx_bump = 0;
    __u32 tx_bump = 0;

    bool clear_ooo = false;

    __u32 now = 0;
    bool drop = true;
    bool served = false; /* rbmc-xdp: in-order GET hit validly consumed → serve */
    #ifndef ACK_COALESCING
    struct bpf_tcp_ack *ack = NULL;
    #endif

    if (!rx_cached_ts[cpu])
        now = bpf_ktime_get_ns();
    else
        now = rx_cached_ts[cpu];

    /* trigger an ACK if there is payload (even if we discard it) */
    if (payload_len) {
        trigger_ack = true;

        #ifndef ACK_COALESCING
        __u32 prod = ack_prod[cpu];
        __u32 cons = ack_cons[cpu];

        // check if ack queue is full
        if (unlikely(cons == ((prod + 1) & (NAPI_BATCH_SIZE - 1)))) {
            xdp_log_err("ack queue is full");
        } else {
            ack = bpf_map_lookup_elem(&bpf_tcp_ack_map, &prod);
            if (unlikely(!ack))
                xdp_log_err("ack is NULL");
        }
        #endif
    }

    struct bpf_cc *cc = bpf_map_lookup_elem(&bpf_cc_map, &c->cc_idx);
    if (unlikely(!cc)) {
        xdp_log_panic("cc is NULL, BUG!!!");
        return XDP_DROP;
    }

    TCP_LOCK(c);
    
    /* ACK processing */
    if (tcph->ack == 1) {
        // update CC
        cc->cnt_rx_acks++;
        if (likely(tcp_valid_rxack(c, ack_seq, &tx_bump)) == 0) {
            if (unlikely(tx_bump > c->tx_sent)) {
                tx_bump = 0;
                /* this is probably caused by retransmission */
                trigger_ack = false;
                goto unlock;
            }
            cc->cnt_rx_ack_bytes += tx_bump;
            if (unlikely(tcph->ece == 1))
                cc->cnt_rx_ecn_bytes += tx_bump;
            
            c->tx_sent -= tx_bump;
            cc->txp = c->tx_sent > 0;

            if (likely(tx_bump)) {
                c->rx_dupack_cnt = 0;
            } 
            /*
            * Fast retransmit -> detect a duplicate ACK if:
            * 1. The ACK number is the same as the largest seen: tcp_valid_rxack() returns 0
            * 2. There is unacknowledged data pending: tx_sent > 0
            * 3. There is no data payload included with the ACK: payload_len == 0
            * 4. There is no window update: c->rx_remote_avail == ((bpf_ntohs(tcph->window)) << TCP_WND_SCALE)
            */
            /* duplicate ack ? */
            else if (unlikely(c->tx_sent && payload_len == 0 && (c->rx_remote_avail == ((bpf_ntohs(tcph->window)) << TCP_WND_SCALE)) && ++c->rx_dupack_cnt == 3)) {
                go_back_pos = fast_retransmit(c, cc);
                xdp_log("Duplicate ACK triggers fast retransmission");
                goto unlock;
            }
        } else {
            trigger_ack = false;
            xdp_log_err("Bad ack");
            goto unlock;
        }
    }

    /* Payload validation */
    #ifdef OOO_RECV
    __u32 trim_start, trim_end;
    if (unlikely(tcp_valid_rxseq_ooo(c, seq, payload_len, &trim_start, &trim_end))) {
        trigger_ack = false;
        xdp_log_err("Bad seq");
        goto unlock;
    }

    payload_off += trim_start;
    if (likely(payload_len >= trim_start + trim_end))
        payload_len -= trim_start + trim_end;
    data_meta->rx.poff = payload_off;
    data_meta->rx.plen = payload_len;

    seq += trim_start;
    data_meta->rx.rx_pos = c->rx_next_pos + (seq - c->rx_next_seq);
    if (data_meta->rx.rx_pos >= c->rx_buf_size)
        data_meta->rx.rx_pos -= c->rx_buf_size;

    /* check if we can add it to the out of order interval */
    if (unlikely(seq != c->rx_next_seq)) {
        if (!payload_len) goto unlock;
        xdp_log("OOO packet, seq(%u), c->rx_next_seq(%u)", seq, c->rx_next_seq);
        if (c->rx_ooo_len == 0) {
            c->rx_ooo_start = seq;
            c->rx_ooo_len = payload_len;
            xdp_log("New segment, ooo_start(%u), ooo_len(%u)", c->rx_ooo_start, c->rx_ooo_len);
        } else if (seq + payload_len == c->rx_ooo_start) {
            c->rx_ooo_start = seq;
            c->rx_ooo_len += payload_len;
            xdp_log("Merge segment, ooo_start(%u), ooo_len(%u)", c->rx_ooo_start, c->rx_ooo_len);
        } else if (c->rx_ooo_start + c->rx_ooo_len == seq) {
            c->rx_ooo_len += payload_len;
            xdp_log("Merge segment, ooo_start(%u), ooo_len(%u)", c->rx_ooo_start, c->rx_ooo_len);
        } else {
            // unfortunately, we can't accept this payload
            payload_len = 0;
            data_meta->rx.plen = POISON_16;
            xdp_log("Drop packet, ooo_start(%u), ooo_len(%u)", c->rx_ooo_start, c->rx_ooo_len);
        }
        // mark this packet is an out-of-order segment
        data_meta->rx.ooo_bump = OOO_SEGMENT_MASK;

        goto unlock;
    }

    #else
        __u32 trim_start, trim_end;
        if (unlikely(tcp_valid_rxseq(c, seq, payload_len, &trim_start, &trim_end))) {
            trigger_ack = false;
            xdp_log_err("Bad seq");
            goto unlock;
        }

        payload_off += trim_start;
        payload_len -= trim_start + trim_end;
        data_meta->rx.poff = payload_off;
        data_meta->rx.plen = payload_len;
        data_meta->rx.rx_pos = c->rx_next_pos;

        xdp_log("Good seq, payload_off(%u), payload_len(%u), trim_start(%u), trim_end(%u)", 
            payload_off, payload_len, trim_start, trim_end);

    #endif

    if (likely(tx_bump || (c->rx_remote_avail < ((bpf_ntohs(tcph->window)) << TCP_WND_SCALE)))) {
        /* update TCP receive window */
        c->rx_remote_avail = (bpf_ntohs(tcph->window)) << TCP_WND_SCALE;
        // bpf_printk("(%u),ack_seq(%u), c->rx_remote_avail(%u), c->tx_sent(%u)", tx_bump, ack_seq, c->rx_remote_avail, c->tx_sent);
    }
    
    /* update RTT estimate */
    if (payload_len && !c->tx_next_ts)
        c->tx_next_ts = ts_val;
    if (likely(tcph->ack == 1 && ts_ecr && tx_bump)) {
        // RTT = t{completion} - t{sent} - t{serialization}
        __u32 rtt = (now - ts_ecr);
        rtt /= 1000; // microseconds
        rtt -= (tx_bump * 1000000) / LINK_BANDWIDTH;
        // bpf_printk("CPU#%u, RTT: %u us", bpf_get_smp_processor_id(), rtt);
        if (likely(rtt < TCP_MAX_RTT)) {
            if (likely(cc->rtt_est))
                cc->rtt_est = (cc->rtt_est * 7 + rtt) / 8;
            else
                cc->rtt_est = rtt;
        }
    }

    /* update TCP state if we have payload */
    if (likely(payload_len)) {
#ifdef RBMC_XDP
        if (cache_hit) {
            /* GET hit served in XDP: ACK the request bytes (advance rx_next_seq)
             * but consume NO app buffer — answered in-kernel, never delivered to
             * the app, so the lib never issues a matching rx_bump. Leaving
             * rx_avail / rx_next_pos untouched avoids draining the advertised
             * receive window (and the app RX ring).
             *
             * Then mark the frame as a no-payload event (plen=POISON) and REDIRECT
             * it (drop=false): the lib recycles it without delivering to the app,
             * and — crucially — the XDP_REDIRECT puts this xsk on the gen flush
             * list, so run_xdp_gen fires THIS NAPI batch and emits the queued
             * serve reply promptly. (gen runs only on an xsk-redirect flush; a
             * bare XDP_DROP would strand the reply in the queue until the next
             * redirected packet → per-op RTO stalls.) All other rx metadata stays
             * POISON so the lib's sync_state is a no-op. */
            c->rx_next_seq += payload_len;
            served = true;
#ifdef RBMC_XDP_V2
            /* v2: if this hit ACKs no lib TX, serve IN-PLACE (the frame becomes
             * the reply, XDP_TX'd by xdp_sock_prog — zero userspace touch). A
             * hit that acks a prior +OK (tx_bump>0) falls through to the v1
             * redirect path below so the ack still reaches the lib. */
            if (likely(cpu < MAX_CPU))
                serve_inplace[cpu] = (tx_bump == 0);
            if (tx_bump == 0)
                goto out;
#endif
            /* CRITICAL: a served GET can still ACK prior lib TX (e.g. a SET's
             * +OK) — the quiescence guard only requires ack_seq==tx_next_seq,
             * and tx_next_seq includes that +OK. Forward the ack (tx_bump) to the
             * lib even though we poison the payload; otherwise the lib never
             * frees the +OK frame and its unack_tx_addrs/txb_sent/
             * pending_free_bytes desync from the XDP layer → tcp_free_buffers
             * pops an empty/short unack list → heap corruption. (sync_state runs
             * for this frame before the plen==POISON recycle.) tx_bump < the
             * RECOVERY_MASK bit, so the lib's go_back_pos branch (same union
             * offset) stays inactive. */
            if (tx_bump)
                data_meta->rx.ack_bytes = tx_bump;
            data_meta->rx.rx_pos = POISON_32;
            data_meta->rx.poff = POISON_16;
            data_meta->rx.plen = POISON_16;
            data_meta->rx.xsk_budget_avail = xsk_budget_avail(c);
            drop = false;
            goto out;
        }
#endif
        rx_bump = payload_len;
        c->rx_avail -= payload_len;
        c->rx_next_pos += payload_len;
        if (c->rx_next_pos >= c->rx_buf_size)
            c->rx_next_pos -= c->rx_buf_size;
        c->rx_next_seq += payload_len;

        // xdp_log("seq(%u), payload_len(%u), c->rx_avail(%u), c->rx_next_pos(%u), c->rx_next_seq(%u)", seq, payload_len, c->rx_avail, c->rx_next_pos, c->rx_next_seq);
        
        /* handle existing out-of-order segments */
        if (unlikely(c->rx_ooo_len)) {
            if (tcp_valid_rxseq_ooo(c, c->rx_ooo_start, c->rx_ooo_len, &trim_start, &trim_end)) {
                /* completely superfluous: drop out of order interval */
                c->rx_ooo_len = 0;
                data_meta->rx.ooo_bump = OOO_CLEAR_MASK;
                trigger_ack = false;
                clear_ooo = true;
            } else {
                c->rx_ooo_start += trim_start;
                c->rx_ooo_len -= trim_start + trim_end;

                // accept out-of-order segments
                if (c->rx_ooo_len && c->rx_ooo_start == c->rx_next_seq) {
                    xdp_log("c->rx_ooo_len(%u), c->rx_ooo_start(%u), c->rx_next_seq(%u)", c->rx_ooo_len, c->rx_ooo_start, c->rx_next_seq);
                    rx_bump += c->rx_ooo_len;
                    c->rx_avail -= c->rx_ooo_len;
                    c->rx_next_pos += c->rx_ooo_len;
                    if (c->rx_next_pos >= c->rx_buf_size)
                        c->rx_next_pos -= c->rx_buf_size;
                    c->rx_next_seq += c->rx_ooo_len;

                    c->rx_ooo_len = 0;
                    // out-of-order segment is processed
                    data_meta->rx.ooo_bump = OOO_FIN_MASK;
                    xdp_log("Out-of-order segment is processed");
                }
            }
        }

        if (unlikely((c->rx_avail >> TCP_WND_SCALE) == 0)) {
            // ebpf realized that the receive buffer is empty,
            // piggyback a signal to lib, once application releases the buffer, force it sync with us
            data_meta->rx.qid |= FORCE_RX_BUMP_MASK;
            // bpf_printk("force");
        }
        // bpf_printk("c->rx_avail = %u", c->rx_avail);
    }

unlock:

    /* redirect this packet to userspace */
    if (likely(rx_bump || tx_bump || go_back_pos || xsk_budget_avail(c)) || clear_ooo) {
        drop = false;
        
        data_meta->rx.xsk_budget_avail = xsk_budget_avail(c);
        xdp_log("xsk_budget_avail(%u)", data_meta->rx.xsk_budget_avail);
        if (tx_bump)
            data_meta->rx.ack_bytes = tx_bump;
        else if (unlikely(go_back_pos)) {
            xdp_log("go_back_pos(%u)", go_back_pos);
            data_meta->rx.go_back_pos = go_back_pos;
            data_meta->rx.go_back_pos |= RECOVERY_MASK;
        }

        if (!payload_len) {
            data_meta->rx.rx_pos = POISON_32;
            data_meta->rx.poff = POISON_16;
            data_meta->rx.plen = POISON_16;
            goto out;
        }

        if (unlikely(data_meta->rx.ooo_bump & OOO_FIN_MASK)) {
            /* piggyback rx_bump */
            data_meta->rx.ooo_bump |= rx_bump;
        }

    }

out:

    if (trigger_ack && !cache_hit) {
        // TODO
        xdp_log("trigger_ack");
        #ifdef ACK_COALESCING
        // make verifier happy
        if (likely(cpu < MAX_CPU) && prev_conn[cpu] == NULL_CONN) {
            prev_conn[cpu] = c->cc_idx;
            prev_conn_li[cpu] = c->local_ip;
            prev_conn_lp[cpu] = c->local_port;
            prev_conn_ri[cpu] = c->remote_ip;
            prev_conn_rp[cpu] = c->remote_port;
            prev_conn_ece[cpu] |= ece;
        }
        #else
        if (likely(cpu < MAX_CPU && ack)) {
            enqueue_ack(c, ack, cpu, now, ece);
        }
        #endif
    }
    TCP_UNLOCK(c);

    /* rbmc-xdp: in-order GET hit validly consumed → signal caller to enqueue a
     * SERVE for the XDP_GEN path (returns XDP_TX as the internal serve signal;
     * the caller turns it into an XDP_DROP of the request frame + a gen reply). */
    if (served)
        return XDP_TX;
    return drop ? XDP_DROP : XDP_REDIRECT;
}

static __always_inline bool is_tcp_syn(struct tcphdr *tcp) {
    if (tcp->syn == 1 && tcp->ack == 0) {
        return true;
    }
    return false;
}

static __always_inline bool is_tcp_syn_ack(struct tcphdr *tcp) {
    if (tcp->syn == 1 && tcp->ack == 1) {
        return true;
    }
    return false;
}

static __always_inline bool is_tcp_rst(struct tcphdr *tcp) {
    return tcp->rst == 1;
}
