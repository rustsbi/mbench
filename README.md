# mbench

A black-box functional conformance and micro-benchmark suite for RISC-V M-mode SBI v3.0 firmware (such as OpenSBI and RustSBI).

- **Conformance + micro-benchmarks** across SBI v3.0 extensions, multi-hart SMP scaling, and trap-and-emulate paths.
- **Automated QEMU runner** with per-case watchdog timeouts and crash/hang recovery.
- **Statistical comparison** with median, IQR, relative ratio, and two-sided Mann-Whitney U tests (`table` and `markdown` output).
- **QEMU & real hardware** support: deterministic `-icount` instruction counting in QEMU or standalone bare-metal image booting on silicon.

## Installation

Install the required Rust bare-metal target and `llvm-tools` (`llvm-objcopy`), and make sure `qemu-system-riscv64` is available in `PATH`:

```bash
rustup target add riscv64imac-unknown-none-elf
rustup component add llvm-tools
```

Install the `mbench` CLI from this repository:

```bash
cargo install --path crates/mbench-cli
```

*(Alternatively, invoke it without installing via `cargo run --release -p mbench-cli -- ...`. When `--kernel` is omitted, `mbench run` auto-builds `mbench-target` and expects to be executed from the repository root.)*

## Usage

### Basic run

Pass an M-mode firmware binary to run the full conformance and benchmark suite on QEMU `virt` (4 harts by default):

```bash
mbench run --bios /path/to/opensbi-riscv64-generic-fw_dynamic.bin
```

Results are saved as JSONL to `results/<bios-stem>.jsonl` (override with `--name` or `--out`).

### Comparing firmwares

Use `--name` to give each firmware a short label for both the output filename (`results/<name>.jsonl`) and the comparison table headers, then pass the captures to `mbench compare` (the first file is the baseline):

```bash
mbench run --bios /path/to/opensbi-fw_dynamic.bin --name opensbi
mbench run --bios /path/to/rustsbi-prototyper-dynamic.bin --name rustsbi

mbench compare results/opensbi.jsonl results/rustsbi.jsonl
```

### Deterministic QEMU runs (`--icount`)

Standard QEMU TCG is not cycle-accurate. For reproducible instruction-level comparisons in QEMU, run with single-hart deterministic instruction counting and compare retired instructions (`instret`):

```bash
mbench run --bios /path/to/opensbi-fw_dynamic.bin --name opensbi-icount --smp 1 --icount
mbench run --bios /path/to/rustsbi-prototyper-dynamic.bin --name rustsbi-icount --smp 1 --icount

mbench compare results/opensbi-icount.jsonl results/rustsbi-icount.jsonl --metric instret
```

### Selecting modes, profiles, and subsets

```bash
# Functional conformance checks only
mbench run --bios /path/to/fw_dynamic.bin --mode check

# Benchmarks only, quick profile (5 trials instead of 11), filtered by prefix
mbench run --bios /path/to/fw_dynamic.bin --mode bench --profile quick --filter rfnc/

# Randomized benchmark order with a reproducible seed (helps detect order bias)
mbench run --bios /path/to/fw_dynamic.bin --order shuffle --seed 0x1234

# Include opt-in I/O (DBCN) and destructive (SUSP) benchmarks
mbench run --bios /path/to/fw_dynamic.bin --io --destructive
```

Available profiles: `quick` (5 trials), `normal` (11 trials, default), and `thorough` (21 trials).

### Exporting results

`mbench compare` supports `cycles` (default), `instret`, and `ns` metrics, plain `table` or `markdown` output, and substring filtering:

```bash
mbench compare results/opensbi.jsonl results/rustsbi.jsonl \
  --metric instret \
  --format markdown \
  --filter time/
```

Run `mbench run --help` and `mbench compare --help` for the full list of options.

## Benchmark & Check Suites

Use any prefix below with `--filter`:

| Category | `--filter` prefixes | Coverage |
| --- | --- | --- |
| Conformance | `conformance/` | ABI contracts, error codes, shared-memory security, SMP/HSM behavior |
| Baselines | `baseline/` | Empty loop, counter read, S-mode trap, and I-cache thrash references |
| Core SBI | `base/`, `time/`, `hsm/` | Extension probing, timer programming (`SBI` vs `Sstc`), hart lifecycle |
| SMP & TLB | `spi/`, `rfnc/`, `scale/` | Cross-hart IPIs, `sfence.vma` shootdowns, multi-hart parallel scaling |
| Telemetry & System | `pmu/`, `fwft/`, `sta/`, `nacl/`, `cppc/` | PMU counters, firmware features, steal-time, nested accel, CPPC |
| Events & Channels | `sse/`, `dbtr/`, `mpxy/` | Supervisor software events, debug triggers, message proxy |
| Trap Emulation | `trap/` | Illegal CSR and misaligned load/store trap handling |
| Opt-in (`--io`, `--destructive`) | `dbcn/`, `susp/` | Debug console throughput/read, system suspend |

## Interpreting Results

`mbench compare` prints five sections: platform/firmware summary, SBI v3.0 extension availability matrix, conformance results, benchmark comparison table, and derived cost decomposition (such as M-mode `ecall` overhead and `SBI` vs `Sstc` timer delta).

- **Benchmark cells**: `<median> [<IQR>]`, followed for non-baseline captures by `(<ratio>; <verdict> <p-value>)` using a two-sided Mann-Whitney U test (`alpha = 0.05`).
- **Verdicts**: `faster`, `slower`, `dist-diff` (same median, different distribution), `ns` (no significant difference), `eq` (identical), or `n<5` (too few samples).
- **Markers & statuses**: `!` flags noisy trials; `HW_NAT` means native execution without M-mode trapping was directly verified via SBI PMU firmware counters (unverified misaligned runs emit normal `PASS` results with heuristic notes); `DELEG_S` means it was delegated directly to S-mode; `SKIP(<reason>)` and `FAIL(<reason>)` indicate skipped or failed cases.
- **Timing caveat**: Treat `cycles` and `ns` from non-`-icount` QEMU TCG runs as approximate; use `--smp 1 --icount` with `--metric instret` in QEMU, or run directly on silicon for real cycle latency.

## Running on Hardware

To run `mbench` on a physical RISC-V board (or a custom QEMU command) without `mbench run`:

1. Build the standalone S-mode binary (set `MBENCH_LOAD_ADDR` if your board loads the S-mode payload at a different 4 KiB-aligned address; default is `0x80200000`, and the RISC-V boot header `text_offset` defaults to `MBENCH_LOAD_ADDR - 0x80000000` or can be overridden via `MBENCH_TEXT_OFFSET`):

```bash
MBENCH_LOAD_ADDR=0x80200000 cargo build --release -p mbench-target --target riscv64imac-unknown-none-elf
llvm-objcopy -O binary \
  target/riscv64imac-unknown-none-elf/release/mbench-target \
  target/riscv64imac-unknown-none-elf/release/mbench.bin
```

*(Note: `mbench.bin` embeds the computed `Image` header `text_offset` for `Image`-aware bootloaders such as U-Boot `booti`. On QEMU `virt` with `-bios`, QEMU ignores `Image.text_offset` on raw binaries and loads them at `0x80200000`, so pass the linked ELF `target/riscv64imac-unknown-none-elf/release/mbench-target` to `--kernel` when booting a non-default `MBENCH_LOAD_ADDR`.)*

2. Boot `mbench.bin` as the S-mode payload behind your M-mode firmware. Optional parameters can be passed via `/chosen/bootargs`:

```text
mode=all|check|bench profile=quick|normal|thorough order=fixed|shuffle seed=<u64|0xhex> filter=<substr> io=1 destructive=1 max_harts=<N>
```

3. Capture the serial console log (e.g., `board-opensbi.log`) and pass the raw log directly to `mbench compare` — non-protocol boot lines are ignored automatically:

```bash
mbench compare board-opensbi.log board-rustsbi.log --metric cycles
```
