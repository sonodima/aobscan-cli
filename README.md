<h1 align="center">AOBscan CLI 🔩</h1>

<div align="center">
  <a href="https://github.com/sonodima/aobscan-cli/releases/latest">
    <img src="https://img.shields.io/github/v/release/sonodima/aobscan-cli?color=pink&label=latest"/>
  </a>
  <a href="https://github.com/sonodima/aobscan-cli/actions?workflow=CI">
    <img src="https://github.com/sonodima/aobscan-cli/workflows/CI/badge.svg"/>
  </a>
  <img src="https://img.shields.io/badge/license-MIT-blue.svg"/>
</div>

<br>

> AOBscan CLI is a command-line utility for multi-threaded AOB memory scanning
> based on the [AOBscan](https://github.com/sonodima/aobscan) library.

## Features

- User-friendly CLI interface
- Single-threaded and multi-threaded file scanning
- IDA-style patterns: `48 8b ? ? ? 48 8c ?? ?? ?? ??`
- Raw hexadecimal strings: `488b??????00`
- Scan for pattern in an object file section _(by name)_
- FAT Mach-O binaries support

## Installation

### 🍺 Homebrew (macOS/Linux)

The easiest way to install **AOBscan CLI** is via [Homebrew](https://brew.sh/),
via the [AOBscan](https://github.com/sonodima/homebrew-aobscan) Homebrew tap:

```sh
brew tap sonodima/aobscan
brew install aobscan
```

You can now launch the program with the `aobscan` command.

### 📦 Pre-built Binaries

Binaries for Windows, Linux and macOS are available on the
[releases](https://github.com/sonodima/aobscan-cli/releases) page.

### 🔩 From Source

> Rust is required to build from source. If you don't have it installed, you can
> install it using [rustup](https://rustup.rs/).

```sh
git clone https://github.com/sonodima/aobscan-cli
cd aobscan-cli
cargo build --release
```

The compiled binary will be located at `target/release/aobscan-cli`

## Read More

If you are interested in benchmarks or learning more about AOB scanning,
check out the [AOBscan](https://github.com/sonodima/aobscan) library,
which is the core of this project.
