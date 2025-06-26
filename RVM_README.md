# RVM — The Rust Virtual Machine

`rvm` is a robust, extensible, and secure virtual machine engine built entirely in Rust. It brings the power and safety of Rust to VM execution, enabling lightning-fast and deterministic program logic for next-generation blockchain, agent, and cloud-native systems.

---

## 🧠 Core Objectives

* 🧩 Execute programmable logic: smart contracts, agent scripts, workflows
* 🔐 Secure sandboxing: strict memory safety, no unintended file/network access
* ⚡ Rust-powered performance: fearless concurrency, zero-cost abstractions
* 📦 Multi-runtime support: native rvm bytecode, optional EVM compatibility, WASM-lite (planned)
* 🧪 Deterministic results: consistent execution across all environments

---

## 🔍 Design Philosophy

* 🛠 **Modular Core:** Plugin-friendly, supports new opcodes or execution formats
* 🏗️ **Safe & Performant:** Takes full advantage of Rust’s type and memory safety guarantees
* 🌱 **Portable:** Library/CLI, embeddable in Rust nodes, serverless runtimes, or agent frameworks
* 🔍 **Auditable:** Easy to test, fuzz, and verify for blockchain and cloud environments

---

## 🛠️ Architecture

```
┌───────────────────────┐
│  rvm-cli              │  <- REPL, test runner, demo CLI
└───────────────────────┘
     │
┌───────────────────────┐
│  rvm-core             │  <- Bytecode interpreter, stack machine, memory/register state
└───────────────────────┘
     │
┌───────────────────────┐
│  rvm-runtime          │  <- Plugins: storage, crypto, syscall hooks, agent APIs
└───────────────────────┘
```

Optional integrations:

* `rvm-ledger` (for Rust ledger/blockchain state)
* `rvm-wallet` (for signing/verification with Rust wallets)
* `rvm-formats/wasm-lite.rs` (planned WASM module)
* `rEVM` (Ethereum compatibility, see below)

---

## ⟳ rEVM Compatibility (Optional)

RVM optionally supports a full **Rust-native EVM** (`rEVM`) module:

* EVM opcode compatibility
* Ethereum account/state model
* Modular hooks for L2/L3 research and ZK circuits (future)
* **Note:** General-purpose by default, not just for Ethereum!

---

## ✨ Features

* Stack-based bytecode execution
* Gas metering, cost-limited execution
* Custom opcodes and plugins (crypto, agent calls)
* WASM-lite (future)
* rEVM/Ethereum compatibility module (optional)
* CLI and Rust crate interfaces
* Embedded signing, verification, and agent orchestration

---

## 🚀 Example CLI Usage

```sh
# Run a demo
rvm demo

# Execute native bytecode (when file support is added)
rvm run contract.rvm

# Execute EVM-compatible bytecode  
rvm evm contract.bin
```

### Quick Start

```bash
# Build and run demo
cargo run -- demo

# Build and run tests
cargo test

# Build optimized release
cargo build --release
```

---

## 🎯 Current Implementation Status

**RVM v0.1.0 is functional and ready for further integration!** ✅

### ✅ Completed Features

* **Core VM Engine** - Stack-based bytecode interpreter with 30+ opcodes
* **Gas Metering** - Deterministic execution cost tracking
* **Smart Contracts** - Contract deployment, execution, and storage
* **rEVM Compatibility** - Ethereum Virtual Machine compatibility layer
* **Runtime Hooks** - Crypto integration (Keccak256, ECRECOVER, signatures)
* **CLI Interface** - Interactive command-line tool with demo mode
* **Test Coverage** - Test suite for all core components

### 🧪 Demo Examples

RVM includes built-in demonstrations:

```bash
# Run the interactive demo
cargo run -- demo
```

**Demo 1: Native RVM Execution**

```
(10 + 20) * 5 = 150
Gas used: 8
```

**Demo 2: EVM Compatibility**

```
(15 + 25) / 2 = 20
Gas used: 15
```

**Demo 3: Smart Contract Runtime**

```
Contract deployed successfully!
Deployment gas: 21000
```

### 🔗 Ecosystem Integration

RVM is designed for seamless integration with your blockchain stack:

| Component   | Status     | Purpose                                       |
| ----------- | ---------- | --------------------------------------------- |
| `rcrypto`   | 🔗 Ready   | Cryptographic primitives (Ed25519, secp256k1) |
| `rwallet`   | 🔗 Ready   | HD wallet integration                         |
| `rsig`      | 🔗 Ready   | Message signing and verification              |
| `ghostlink` | 🔗 Ready   | gRPC communication with Zig/Rust blockchain   |
| `cns`       | 🔗 Ready   | Name Service for domain resolution            |
| `tokioz`    | 🔄 Planned | Async runtime for concurrent execution        |

---

## 🔐 Use Cases

* Smart contract and agent execution on-chain
* Local contract testing and replay
* Signature and payload verification
* Deterministic logic for agents (e.g., Jarvis)
* Programmatic workflows in distributed apps

---

## License

Apache-2.0 — Designed for robust, safe, and modular blockchain, agent, and distributed system applications.

---

> Mirror/bridge project: A full-featured Zig implementation is available at [`ghostbridge`](https://github.com/ghostkellz/ghostbridge) for Zig-centric stacks.

