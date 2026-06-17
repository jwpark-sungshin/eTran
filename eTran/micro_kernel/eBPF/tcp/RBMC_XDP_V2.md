# rbmc-xdp v2 — in-place serve (BMC-style) + kernel frame-recycle

**Branch:** `hookshift-v2` (eTran submodule), based on v1 commit `f0d9bac`.
**Status (2026-06-17):** BPF code written and **compiles** (`-DRBMC_XDP -DRBMC_XDP_V2`,
clang-16 rc=0). Kernel recycle patch **designed, not yet implemented/tested**.
**Do NOT run a `-DRBMC_XDP_V2` build on the current (unpatched) kernel — it leaks
UMEM frames** (see below). v1 (`-DRBMC_XDP` only) is unaffected and remains the
verified, eval'd version.

## Why v2

v1 serves a GET hit by routing the reply through eTran's XDP_GEN path and
REDIRECTing the (poisoned) request frame to the lib to trigger gen. That costs
**one userspace (lib) touch per serve** + a fresh gen frame + per-batch deferral.
v2 does what BMC does for UDP, for TCP: **rewrite the request frame in place into
the reply and XDP_TX it** — zero userspace touch, single frame, synchronous.

The only thing that blocks the in-place XDP_TX is frame recycling: an XDP_TX'd
UMEM (fill-ring) frame's completion lands in the AF_XDP completion ring (cq), and
eTran's lib cq-drain only recycles slowpath/FLAG_SYNC frames AND is gated on
`outstanding` (bumped only by lib TX submits) — a pure GET-hit never bumps it, so
the serve frame is never recycled → the buffer pool drains → hang. That leak is
exactly why v1 avoids in-place XDP_TX. **v2 fixes the recycle in the kernel.**

## BPF code (already in this branch, gated `RBMC_XDP_V2`)

- `rbmc_xdp.h` — `rbmc_xdp_build_reply_inplace()`: the BMC-style in-place rewrite
  (swap addrs/ports, grow tail, copy the cached reply from per-CPU scratch, fill
  TCP/IP via `fill_tcp_hdr`/`fill_ip_hdr`, advance ONLY `c->tx_next_seq`), returns
  `XDP_TX`. Reused (restored) from the original pre-v1 serve.
- `tcp.h` — `serve_inplace[MAX_CPU]` per-CPU flag; in `tcp_rx_process`'s cache-hit
  branch: `serve_inplace[cpu] = (tx_bump == 0)`; if `tx_bump==0` → `goto out`
  (in-place), else fall through to the v1 redirect+gen path (so a GET that ACKs a
  prior SET's +OK still forwards that ack to the lib — the in-place frame never
  visits the lib, so it cannot carry the ack).
- `main.c` — `xdp_sock_prog`: on the serve signal, if `serve_inplace[cpu]` →
  `rbmc_xdp_build_reply_inplace()` (XDP_TX); else → v1 `enqueue_serve` + redirect.

So v2 is a **hybrid**: in-place fast path for the common GET hit (tx_bump==0, 0
userspace), v1 gen+redirect fallback for the rare hit that acks lib TX (tx_bump>0,
≈ the first GET after each SET response; 0% in GET-only).

## REQUIRED kernel patch (designed, TODO: implement + test)

Add to `etran-on-6.6.142.patch` (mlx5). The eTran patch already has a completion
mode-switch in `mlx5e_free_xdpsq_desc` (`drivers/.../mlx5/core/en/xdp.c`) with
modes `MLX5E_XDP_XMIT_MODE_XSK` (→ `xsk_tx_completed`, cq), `..._XSK_OOO_COMP`
(→ `xsk_ooo_cq`), `..._XSK_NO_COMP` (→ nothing), `..._FRAME` (page-pool). None of
these returns a UMEM frame to the **fill ring**, which is what an in-place serve
needs. Three changes:

1. **`en/xdp.h`** — add enum `MLX5E_XDP_XMIT_MODE_XSK_RECYCLE`.
2. **`en/xdp.c` `mlx5e_xmit_xdp_buff`** (the RX-path XDP_TX handler — the path a
   program's `XDP_TX` return takes, distinct from the ndo `mlx5e_xdp_xmit`
   REDIRECT path): for a ZC (xsk) RX buff being XDP_TX'd, push xdpi with
   `MODE_XSK_RECYCLE` + `frame.desc_addr` instead of the default XSK mode.
   Plain/v1 eTran never returns XDP_TX from `xdp_sock_prog`, so **all** RX-path
   XDP_TX on the eTran ZC queue is the v2 serve — no per-frame flag needed (or add
   one for safety, mirroring `XDP_FLAGS_XSK_QUEUEING`).
3. **`en/xdp.c` `mlx5e_free_xdpsq_desc`** — handle `MODE_XSK_RECYCLE`: return
   `desc_addr` to the xsk pool's **fill** ring so the frame is available for RX
   again, instead of `xsk_tx_completed` (cq). Finalize the exact API against
   `net/xdp/xsk_buff_pool.c` (the eTran patch already touches it) — candidates:
   `xsk_buff_free`/`xp_release` of the ZC buff, or produce `desc_addr` to the fill
   queue + kick. This is the one line to verify empirically.

Net: the serve frame round-trips fill → RX → XDP_TX → fill, entirely in-kernel,
no cq, no lib. No `outstanding` gating, no leak.

## Build / deploy / test

```
# 1. deploy v2 source (this branch) to the server tcp eBPF dir
scp tcp.h main.c rbmc_xdp.h node0@server:/home/node0/eTran/eTran/micro_kernel/eBPF/tcp/
# 2. add the recycle patch to etran-on-6.6.142.patch, rebuild + install the kernel
#    (grub-reboot the etran+ entry; 6.6.x boots on this box via grub one-shot)
# 3. build the v2 eBPF
/home/node0/build-rbmcxdp.sh "-DRBMC_XDP -DRBMC_XDP_V2"   # (chown main.o node0 first if root-owned)
# 4. verifier-load + the leak/mixed tests (MUST pass on the patched kernel):
bash /home/node0/rbmcxdp-leaktest.sh      # GET-only -n200k + mixed (no hang, no crash)
bash /home/node0/mixed-scale.sh           # 200-conn mixed, SET-heavy
# 5. A/B vs v1: run rbmcxdp-tl.sh with the v2 build and compare to v1
#    (rbmcxdp/rbmcxdp-tl.csv) — expect lower CPU/req and lower low-load latency
#    (no per-serve lib touch, no gen deferral).
```

**Verify before trusting:** (a) verifier loads the `-DRBMC_XDP_V2` object;
(b) GET-only -n200k does NOT hang (confirms the kernel recycle works — without it
this is the original leak); (c) mixed (SET+GET) does not crash (the tx_bump>0
fallback path is exercised); (d) the in-place serve actually reaches the wire
(tcpdump: server→client reply, correct cksum/seq), since this path bypasses the
lib entirely.

## Expected result

v2 should match v1's throughput and **improve** low-load latency (no gen
per-NAPI-batch deferral) and CPU/req (no per-serve lib descriptor + no fresh gen
frame). The headline comparison is v2-vs-v1 on the same T-L sweep
(`rbmcxdp-tl.sh`) — this is the "purity" the system-4 story wants (truly zero
userspace on the hit path).
