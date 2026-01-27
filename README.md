<p align="center">
  <img src="logo.svg" alt="na logo" width="200">
</p>

# na

Run npm audit. <!-- FASTEST_SPEEDUP_START -->72.6<!-- FASTEST_SPEEDUP_END -->x faster.

A zero-overhead npm audit tool written in Rust. No Node.js startup, no npm overhead—just your vulnerabilities.

## Benchmarks

<!-- BENCHMARK_START -->
| Tool | Time | Vulnerabilities |
|------|------|-----------------|
| na | 630ms | 698 (total) |
| npm audit | 45.7s | 428 (deduplicated) |

*Measured on macOS (Apple Silicon). Your mileage may vary.*
<!-- BENCHMARK_END -->

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/dawsbot/na/main/install.sh | sh
```

Works on macOS, Linux, and Windows (via Git Bash/WSL).

## Usage

```bash
# Run audit on current project
na
```

## Why is it faster?

**No Node.js startup.** npm bootstraps Node.js before doing anything. That's 50-100ms before your audit even starts. `na` is a native binary—it starts instantly.

**Minimal parsing.** We only read what's needed from package-lock.json. No dependency resolution, no extra processing. Just vulnerabilities.

**Tiny binary.** No runtime, no GC, no framework. Just machine code.

## Build from source

```bash
git clone https://github.com/dawsbot/na
cd na
cargo build --release
cp target/release/na /usr/local/bin/
```

## Status

Experimental. Works on my machine. Report issues at [GitHub](https://github.com/dawsbot/na/issues).

## License

MIT
