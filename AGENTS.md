# AGENTS.md

`mbench` is a black-box micro-benchmark and functional conformance suite for RISC-V M-mode SBI v3.0 firmware (such as OpenSBI and RustSBI).

## Workspace Layout

- `crates/mbench-core/` — Shared `#![no_std]` library (with optional `std` support) providing the benchmarking engine, conformance runner, statistics, configuration, and wire protocol.
- `crates/mbench-target/` — Bare-metal RISC-V S-mode payload (`riscv64imac-unknown-none-elf`) containing platform support, SBI bindings, and the conformance and benchmark suites.
- `crates/mbench-cli/` — Host CLI (`mbench run` and `mbench compare`) for running evaluations on QEMU and comparing captured results.

## Build and Verification

`mbench-target` is excluded from default workspace members and must be linted/built explicitly for `riscv64imac-unknown-none-elf`; `mbench-core` must also stay clean under `--no-default-features`.

```bash
# Host checks (mbench-core + mbench-cli)
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo clippy -p mbench-core --no-default-features -- -D warnings
cargo test --all-features
cargo test -p mbench-core --no-default-features

# Bare-metal target checks and image build
cargo clippy -p mbench-target --target riscv64imac-unknown-none-elf -- -D warnings
cargo build --release -p mbench-target --target riscv64imac-unknown-none-elf
llvm-objcopy -O binary \
  target/riscv64imac-unknown-none-elf/release/mbench-target \
  target/riscv64imac-unknown-none-elf/release/mbench.bin
```
