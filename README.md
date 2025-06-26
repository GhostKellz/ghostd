# 👻 ghostd: The GhostChain Node Daemon

`ghostd` is the core daemon that powers the **GhostChain** decentralized network. It executes smart contracts, syncs blocks, validates transactions, and serves as the backbone of Web5 infrastructure through native support for QUIC, IPv6, and zero-trust identity authentication via ZID.

---

## 🚀 Core Responsibilities

* 📦 Accept, validate, and broadcast transactions
* ⛓️ Maintain blockchain state and consensus
* 🧠 Run contracts using `zvm` (WASM) or `rvm` (EVM)
* 📡 Communicate over gRPC (via GhostBridge or directly)
* 🔑 Verify identities and signatures using ZID
* 💾 Interface with `zledger` for storage and audit



---

## 🔧 Architecture

```
ghostd/
├── src/
│   ├── main.rs          # Entrypoint
│   ├── rpc.rs           # gRPC service handlers (Tonic)
│   ├── chain.rs         # Block/mempool/tx validation
│   ├── state.rs         # Ledger + state machine
│   ├── signer.rs        # ZID + zcrypto identity checks
│   ├── vm/
│   │   ├── mod.rs       # VM interface
│   │   ├── zvm.rs       # WASM runtime
│   │   └── rvm.rs       # EVM-compatible runtime
│   └── ffi/
│       └── realid.rs    # FFI wrapper to Zig `realid`
├── proto/ghostd.proto   # gRPC API
├── Cargo.toml
└── DEPENDS.md

```

---

## 📡 gRPC API (via tonic)

* `SubmitTransaction` – Accept a signed transaction
* `QueryState` – Fetch account or contract state
* `DeployContract` – Deploy ZVM or RVM bytecode
* `RunContract` – Execute view/pure method calls
* `GetBlock`, `GetTx`, `GetLogs`, `GetReceipt`

> Communicates securely over QUIC via GhostBridge or Wraith.

---

## 🧠 VM Support

* `zvm` – For WASM-based smart contracts (lightweight)
* `rvm` – For Ethereum-compatible EVM bytecode (ERC20, ERC721)
* Future: zkVM / plugins

---

## 🔐 Identity and Security

* Uses realID for identity verification and signing
* Compatible with `walletd` and `zns`
* Validator authentication and block signature enforcement

---

## 🧬 Integration Points

* `walletd` – Receives signed transactions and contract calls
* `zledger` – Stores finalized blocks and state changes
* `zns` – Resolves domain-linked identities for contract access
* `ghostbridge` – Handles QUIC/gRPC multiplexing

---

## ✅ Features

* 🔁 Gossip protocol for peer discovery
* 📦 Smart contract execution
* ⚡ QUIC-based RPC via Wraith or direct
* 🔐 realID-powered access control
* 🌍 IPv6-native addressing

---

## 📜 License

MIT © Christopher Kelley

