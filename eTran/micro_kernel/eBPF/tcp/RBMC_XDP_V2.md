# rbmc-xdp v2 — in-place serve (BMC-style), WORKS on the stock eTran kernel

**Branch:** `hookshift-v2` (eTran submodule), based on v1 commit `f0d9bac`.
**Status (2026-06-18):** **WORKING.** Verified on the existing `6.6.142-etran+`
kernel — **no kernel patch needed.** GET-only 200k in-place serves (no hang),
mixed single + 200-conn, SET-heavy — all pass; grow_fail=0, hit==serve_xdp.

## What v2 is

Serve a GET hit the way BMC serves UDP: **rewrite the request frame in place into
the reply and XDP_TX it** (`rbmc_xdp_build_reply_inplace`), instead of v1's
XDP_GEN route. Zero userspace (lib) touch, synchronous (no per-NAPI-batch gen
deferral). Gated `-DRBMC_XDP_V2` (dormant without the flag → v1 behavior byte-
preserved).

Dispatch (`tcp_rx_process` cache-hit branch + `xdp_sock_prog`):
- **tx_bump == 0 → in-place** (the common GET hit): `rbmc_xdp_build_reply_inplace`
  → XDP_TX. `serve_inplace[cpu]` carries the decision.
- **tx_bump > 0 → v1 fallback** (the hit ACKs a prior SET's +OK; the in-place
  frame never visits the lib so it can't carry that ack): `enqueue_serve` +
  redirect, which forwards the ack. Rare (≈ first GET after each SET response;
  0% in GET-only).

## Why no kernel patch is needed (the v1 "frame leak" was a misdiagnosis)

mlx5's RX-path XDP_TX of a ZC (xsk/UMEM) frame does NOT transmit the UMEM frame
directly. In `mlx5e_xmit_xdp_buff` (en/xdp.c), `xdp_convert_buff_to_frame` on a
`MEM_TYPE_XSK_BUFF_POOL` buff **copies the data into a freshly allocated page,
returns the UMEM frame to the pool immediately (ZCA), and transmits the copy as
`MLX5E_XDP_XMIT_MODE_FRAME`** — freed via `xdp_return_frame` on TX completion. So
the served frame's UMEM buffer is recycled by the driver and the transmitted copy
is a page-pool page the kernel frees. **Neither leaks; nothing lands in the AF_XDP
cq.** The earlier "serve XDP_TX → cq → lib ignores it (outstanding-gated)" analysis
was wrong for this path. v1's high-volume hang was the **rx_avail / receive-window
drain** (served GETs advanced rx_avail without delivery), which the v1 BPF fix
(advance only `rx_next_seq` on a cache hit) already cured — v2 inherits that fix,
so in-place XDP_TX no longer hangs.

Trade-off vs v1: v2 still pays one per-serve page alloc+copy (mlx5's copy-to-page),
comparable to v1's fresh gen frame. The v2 win is **no per-serve lib touch + no
gen deferral** → lower CPU/req and lower (especially low-load) latency. See the
v2-vs-v1 T-L A/B (`rbmcxdp-tl-v2.csv` vs `rbmcxdp-tl.csv`).

## Optional future optimization (NOT needed for v2 to work): true zero-copy

To avoid mlx5's per-serve copy-to-page, a kernel patch could transmit the UMEM
frame directly and recycle it to the fill ring on completion: add
`MLX5E_XDP_XMIT_MODE_XSK_RECYCLE` to mlx5 en/xdp.{c,h}, tag the RX-path XDP_TX,
and on completion return `desc_addr` to the fill ring (leverages eTran's existing
XDP-TX completion mode-switch + `XDP_FLAGS_XSK_QUEUEING` machinery). This is a
perf optimization (one fewer copy), not a correctness requirement — defer unless
the A/B shows the copy-to-page is a bottleneck.

## Build / deploy / test (no kernel rebuild)

```
# deploy v2 source (this branch) to the server tcp eBPF dir
scp tcp.h main.c rbmc_xdp.h node0@server:/home/node0/eTran/eTran/micro_kernel/eBPF/tcp/
# build v2 (chown main.o to node0 first if a prior sudo build left it root-owned)
/home/node0/build-rbmcxdp.sh "-DRBMC_XDP -DRBMC_XDP_V2"
# tests (BUILD_FLAGS selects the version; harnesses parameterized):
BUILD_FLAGS="-DRBMC_XDP -DRBMC_XDP_V2" bash /home/node0/rbmcxdp-leaktest.sh   # GET-only 200k + mixed
BUILD_FLAGS="-DRBMC_XDP -DRBMC_XDP_V2" bash /home/node0/mixed-scale.sh        # 200-conn mixed, SET-heavy
# T-L A/B (v2 vs v1):
BUILD_FLAGS="-DRBMC_XDP -DRBMC_XDP_V2" SYSTAG=rbmc-xdp-v2 SFX=-v2 bash /home/node0/rbmcxdp-tl.sh
```

v1 is `-DRBMC_XDP` (no V2 flag); v2 is `-DRBMC_XDP -DRBMC_XDP_V2`. Both build from
the same source on branch `hookshift-v2`.
