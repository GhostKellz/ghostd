# ZVM — The Zig Virtual Machine

`zvm` is a lightweight, modular, and secure virtual machine engine built entirely in Zig. Inspired by the performance and control ethos of Zig, `zvm` is designed to be:

* **Minimal by design** — clean, simple execution engine
* **Customizable** — supports new instruction sets (e.g., zEVM-style bytecode)
* **Secure** — strict memory controls with Zig’s runtime safety
* **Portable** — embeddable in CLIs, nodes, smart wallets, and more

---

## 🧠 Core Objectives

* 🧩 Execute programmable logic: smart contracts, signed scripts, workflows
* 🔐 Run in a sandboxed environment: no external file/network access unless declared
* ⚙️ Support multi-runtime formats: wasm-lite, zvm bytecode, and (optionally) zEVM-style execution
* 🧪 Deterministic computation: all operations produce the same result across environments

---

## 🔍 Design Philosophy

`zvm` is not a full blockchain runtime by default — it's a secure execution layer:

* 🛠 **Built for modularity**: easily extendable with custom opcodes
* 🧱 **Memory-constrained**: ideal for edge computing and embedded validation
* 🔄 **State machine-friendly**: integrates well with `zledger`, `zwallet`, and smart contract logic
* 🔍 **Auditable & deterministic**: encourages formal verification and testing

---

## 🛠️ Architecture

```
┌───────────────────────┐
│  zvm-cli              │  <- local test runner / REPL
└───────────────────────┘
     │
┌───────────────────────┐
│  zvm-core             │  <- bytecode interpreter, stack machine, memory/register state
└───────────────────────┘
     │
┌───────────────────────┐
│  zvm-runtime          │  <- plugin functions: storage, signing, I/O hooks
└───────────────────────┘
```

Optional add-ons:

* `zvm-ledger` (calls into `zledger`)
* `zvm-wallet` (validates against `zsig` signatures)
* `zvm-formats/wasm-lite.zig` (planned)
* `zvm-formats/zevm.zig` (optional EVM compatibility)

---

## ⟳ zEVM Compatibility (Optional)

We may explore compatibility or feature sharing with [`zEVM`](https://github.com/ziglang/zevm):

* EVM opcode set
* Ethereum state machine model
* Potential for full L2 sandbox support in Zig

Unlike `zEVM`, `zvm` aims for:

* More general-purpose virtual machines (not just Ethereum)
* Smaller, embeddable runtimes (e.g., <100KB for minimal build)
* A modular format stack with wasm-lite and zvm-native bytecode for Ghostchain

---

## ✨ Features

* Bytecode execution (custom or EVM-like)
* Deterministic gas metering / instruction counting
* Hookable system calls (via `zvm-runtime`)
* WASM-lite compilation target (future)
* Optional zEVM compatibility module
* Embedded signing + verification (via `zsig`)

---

## Example CLI

```sh
# Run native ZVM bytecode
zvm demo

# Execute ZVM native bytecode (when file support is added)
zvm run contract.zvm

# Execute EVM-compatible bytecode  
zvm evm contract.bin

# Run built-in demonstration
zvm demo
```

### Quick Start

```bash
# Build and run demo
zig build run -- demo

# Build and run tests
zig build test

# Build optimized release
zig build -Doptimize=ReleaseFast
```

---

## 🎯 Current Implementation Status

**ZVM v0.1.0 is now fully functional!** ✅

### ✅ Completed Features

* **Core VM Engine** - Stack-based bytecode interpreter with 30+ opcodes
* **Gas Metering** - Deterministic execution cost tracking
* **Smart Contracts** - Contract deployment, execution, and storage
* **ZEVM Compatibility** - Full Ethereum Virtual Machine compatibility layer
* **Runtime Hooks** - Crypto integration (Keccak256, ECRECOVER, signatures)
* **CLI Interface** - Interactive command-line tool with demo mode
* **Test Coverage** - Comprehensive test suite for all components

### 🧪 Demo Examples

ZVM includes built-in demonstrations:

```bash
# Run the interactive demo
zig build run -- demo
```

**Demo 1: Native ZVM Execution**
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

ZVM is designed to integrate with the complete **GhostChain** ecosystem:

| Component | Status | Purpose |
|-----------|--------|---------|
| `zcrypto` | 🔗 Ready | Cryptographic primitives (Ed25519, secp256k1) |
| `zwallet` | 🔗 Ready | HD wallet integration |
| `zsig` | 🔗 Ready | Message signing and verification |
| `ghostbridge` | 🔗 Ready | gRPC communication with Rust blockchain |
| `cns` | 🔗 Ready | Custom Name Service for domain resolution |
| `tokioz` | 🔄 Planned | Async runtime for concurrent execution |

---

## 🔐 Use Cases

* Executing governance actions on-chain
* Smart contract testing and replay locally
* Verifying signed payloads in IoT/embedded workflows
* Running deterministic agent logic for `Jarvis`
* Powering programmable logic inside Ghostchain

---

## License

MIT — Designed for modular integration with the GhostKellz stack.

