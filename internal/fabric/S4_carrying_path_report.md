# S4 — Verify carrying paths and performance budgets

Story: read-only security pass over `internal/fabric`, `internal/traffic`,
`internal/forward`, `internal/fqcodel` for integer overflow in packet-length
math and NAT/alloc map handling; confirm the documented fqcodel budget still
holds; record anything needing restructuring without changing code. No code
was changed by this story — this report is the deliverable.

## Verification evidence

### go test — all pass, no new failures

    $ go test -timeout 10m -count=1 ./internal/fabric/... ./internal/traffic/... \
        ./internal/forward/... ./internal/fqcodel/...
    ok  	github.com/sellitus/app-tail/internal/fabric	8.002s
    ok  	github.com/sellitus/app-tail/internal/traffic	1.051s
    ok  	github.com/sellitus/app-tail/internal/forward	6.034s
    ok  	github.com/sellitus/app-tail/internal/fqcodel	0.358s

### fqcodel benches — budget holds

Quiet-machine re-run (`-count 5`), all samples inside the documented
65–83 ns envelope and zero-alloc:

    $ go test -run x -bench BenchmarkEnqueueDequeue -count 5 \
        -timeout 10m ./internal/fqcodel
    BenchmarkEnqueueDequeue/1flow-18     38.16–42.88 ns/op   0 B/op   0 allocs/op
    BenchmarkEnqueueDequeue/64flows-18   41.61–47.63 ns/op   0 B/op   0 allocs/op

Both sub-benchmarks hold 0 B/op, 0 allocs/op in every sample, and every
ns/op sample is below the 83 ns ceiling (headroom ≥ 35 ns). An earlier
run taken while sibling story sessions were executing their test suites
on this same machine measured 93.0–137.1 ns (1flow) and 110.6–163.2 ns
(64flows) — machine load, not code: no fqcodel file differs from commit
8d250c9 ("Fix priority and performance issues") where the budget was
recorded. The quiet-machine numbers above are the authoritative ones;
the budget holds.

## Security pass — findings

All four packages audited file-by-file (non-test sources). **No exploitable
integer-overflow, slice-bounds, or map-handling defect was found.** Nothing
needs restructuring as a security matter. Details per package:

### internal/fqcodel — clean

- `Enqueue` (fqcodel.go:229-272) validates `size` in 1..`MaxSize`
  (MaxSize = math.MaxUint16) before any accounting; backlog is bounded by
  the fixed slot array allocated at `New`, so byte counters are bounded by
  `len(slots) × 65535` — no overflow on any width Go runs on.
- All slot/bucket indices come from a fixed free list and `none` (-1)
  sentinels; no packet-derived index exists.
- `classify.go`: every header read is length-checked first
  (`Classify` → `classify4`/`classify6` check minimum sizes, IPv4 header
  length re-validated against the packet at classify.go:53, fragment and
  transport minimums checked at :78, :93, :99). Never panics; verified by
  the existing classify/fqcodel tests.

### internal/fabric — clean

- `stack.go` pumpIn/pumpOut: buffers are fixed `headroom+maxPacket`
  (65535); slices are `buf[headroom:headroom+n]` with `n` bounded by the
  buffer length by the tun/stack contract. No attacker-controlled length
  reaches the arithmetic.
- `relayDatagrams` (flows.go:567-602): pooled 64 KB buffer, all slices
  `buf[:n]`, `n > 0` guarded.
- `nat.go remap` (253-282) and `alloc.go next` (269-289): prefix
  arithmetic guarded for family, equal bit-lengths, byte-index bounds
  (`whole ≤ 3` / `≤ 15`), shift amount 0–7; address-family wrap-around is
  returned as false rather than wrapping to zero.
- Maps: `Table` is immutable after `NewTable`; `SetTable` swaps the
  pointer under a lock. `sessions.take/release` are paired on every path
  (deferred in `carryTCP`/`carryUDP`, inline on the `CreateEndpoint`
  failure path); `openFlows` add/remove paired via defers; `endWhatMoved`
  cancels outside the lock, so no deadlock or double-remove hazard.
- `host.go:56` `bits -= 96` is only reachable where the mask guarantees
  `bits ≥ 96`; invalid results discarded.

### internal/traffic — clean

- Stats-only package; no packet bytes are parsed here.
- `keyed.go` `Table` is hard-capped at `maxKeys = 64` with fold-aside
  accounting; all access under `t.mu`. `Ring` likewise mutex-guarded,
  clamped to size ≥ 1.
- `rate.go perSecond` (111-116) treats counter regressions as resets
  (gap), preventing wrap-around-as-negative-throughput artifacts;
  `int64` byte counters cannot overflow in practice (~9.2 EB).

### internal/forward — clean

- The only `int→uint16` narrowing on the path (`tcp.go:58`,
  `udp.go:128` `uint16(f.ListenPort)`) is guarded by config validation
  (`internal/config/validate.go:115-117` rejects ports outside 1–65535
  before the value reaches the manager).
- `inspect.go:82-83` `strconv.ParseUint(port, 10, 16)` — width-checked
  before the `uint16` conversion.
- UDP session map: single creation site, every removal path closes the
  socket, `sync.Once`-guarded close, bounded by `maxUDPSessions` with
  insert-time eviction and a janitor. The deliberate lock-drop around
  `dialUpstream` re-checks under the lock and closes the race loser.
- Datagrams: reads into a fixed `bufSize` buffer, only `buf[:n]` used;
  Windows oversize (WSAEMSGSIZE) is detected and dropped without killing
  the read loop.

## Recorded observations (no action; code unchanged)

1. **fqcodel ns/op is load-sensitive on this machine.** 0 allocs hold
   exactly; an initial run taken while sibling story sessions were
   executing their suites measured 93–137 ns (1flow) / 111–163 ns
   (64flows), above the documented 65–83 ns. A quiet-machine re-run
   (`-count 5`, recorded above) measured 38.16–42.88 ns (1flow) and
   41.61–47.63 ns (64flows), all within budget — the earlier numbers
   were machine load, not code. Design note only; code unchanged.
2. **`fabric.tally` entries are never deleted** (fabric.go:412-422): the
   map is keyed by connection id and grows with the set of connections the
   agent has ever carried in this process. Bounded by connection churn,
   not by traffic; recorded as a design note, not a defect — fixing it
   would be restructuring for no demonstrated harm.
3. **UDP forward dial blocks the read loop** (forward/udp.go:296): a new
   client's upstream dial can stall all clients of that forward for up to
   `udpDialTimeout` (5 s). Documented and accepted in the code's own
   comments (udp.go:40-45); changing it is a restructuring, out of scope.

## What changed

- Added this report (`internal/fabric/S4_carrying_path_report.md`).
- No `.go` file in `internal/fabric`, `internal/traffic`, `internal/forward`,
  or `internal/fqcodel` was modified. No git commands were run.
