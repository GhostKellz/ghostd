✅ Required Modules for ghostd
Module	Use In ghostd	Source / Reason
zvm	WASM-based smart contract runtime	Internal plugin or crate
rvm	EVM-compatible smart contract engine	Internal plugin or crate
zledger	State, balance, and ledger audit layer	Storage + tx replay
realid	Validator identity + signature verification (block signing)	FFI or native
zcrypto	Hashing, Merkle trees, basic crypto ops	Needed by consensus/ledger
ghostbridge	gRPC/QUIC multiplexing, connects to Wraith or other daemons	Handles incoming streams
zwallet (read-only)	Only if needed for internal tx construction/test harness	Optional, usually only walletd
cns/zns	Optional for resolving domain identities / validator registry	Optional unless DNS-based lookup is needed


zig projects
github.com/ghostkellz/zcrypto  
github.com/ghostkellz/zwallet
github.com/ghostkellz/realid
github.com/ghostkellz/zledger 
github.com/ghostkellz/zvm 
github.com/ghostkellz/ghostbridge

github.com/ghostkellz/zns
github.com/ghostkellz/cns 

Ghostchain blockchain is built on rust 
wasm like components are built in zvm / zevm

