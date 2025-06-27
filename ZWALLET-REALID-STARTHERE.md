# 🪙 ZWallet Integration with RealID

**Quick start guide for integrating RealID zero-trust identity into zwallet cryptocurrency wallet projects**

---

## 🎯 Overview

This guide shows how to leverage the RealID library as a foundational dependency for **zwallet** - a cryptocurrency wallet that uses zero-trust identity for enhanced security. RealID provides deterministic key generation from passphrases with optional device binding.

### Key Benefits for ZWallet
- **Deterministic Identity**: Same passphrase always generates same identity
- **Device Binding**: Optional hardware fingerprinting for added security  
- **Zero-Trust**: No reliance on external identity providers
- **Cross-Platform**: Works consistently across devices
- **Quantum-Resistant**: Built on Ed25519 cryptography

---

## 🔧 Quick Setup

### 1. Add RealID Dependency

Add to your `build.zig.zon`:

```zig
.dependencies = .{
    .realid = .{
        .path = "../realid", // Local path to realID
        // OR remote:
        // .url = "https://github.com/your-org/realid/archive/v0.2.0.tar.gz",
        // .hash = "...",
    },
},
```

Update your `build.zig`:

```zig
const realid_dep = b.dependency("realid", .{
    .target = target,
    .optimize = optimize,
});

exe.root_module.addImport("realid", realid_dep.module("realid"));
```

### 2. Basic ZWallet Integration

```zig
const std = @import("std");
const realid = @import("realid");

pub const ZWallet = struct {
    master_identity: realid.RealIDKeyPair,
    qid: realid.QID,
    device_bound: bool,
    allocator: std.mem.Allocator,
    
    const Self = @This();
    
    /// Create wallet from passphrase (deterministic)
    pub fn fromPassphrase(allocator: std.mem.Allocator, passphrase: []const u8) !Self {
        const keypair = try realid.realid_generate_from_passphrase(passphrase);
        const qid = realid.realid_qid_from_pubkey(keypair.public_key);
        
        return Self{
            .master_identity = keypair,
            .qid = qid,
            .device_bound = false,
            .allocator = allocator,
        };
    }
    
    /// Create device-bound wallet (hardware fingerprinting)
    pub fn fromPassphraseWithDevice(allocator: std.mem.Allocator, passphrase: []const u8) !Self {
        const device_fp = try realid.generate_device_fingerprint(allocator);
        const keypair = try realid.realid_generate_from_passphrase_with_device(passphrase, device_fp);
        const qid = realid.realid_qid_from_pubkey(keypair.public_key);
        
        return Self{
            .master_identity = keypair,
            .qid = qid,
            .device_bound = true,
            .allocator = allocator,
        };
    }
    
    /// Get wallet address as hex string
    pub fn getAddress(self: Self, buffer: []u8) ![]u8 {
        return realid.qid.qid_to_string(self.qid, buffer);
    }
    
    /// Sign transaction data
    pub fn signTransaction(self: Self, tx_data: []const u8) !realid.RealIDSignature {
        return realid.realid_sign(tx_data, self.master_identity.private_key);
    }
    
    /// Verify transaction signature
    pub fn verifyTransaction(self: Self, tx_data: []const u8, signature: realid.RealIDSignature) bool {
        return realid.realid_verify(signature, tx_data, self.master_identity.public_key);
    }
};
```

---

## 💰 Cryptocurrency Integration Patterns

### Bitcoin-Style Wallet

```zig
pub const BitcoinWallet = struct {
    realid_identity: ZWallet,
    
    pub fn init(allocator: std.mem.Allocator, passphrase: []const u8, device_bound: bool) !BitcoinWallet {
        const wallet = if (device_bound) 
            try ZWallet.fromPassphraseWithDevice(allocator, passphrase)
        else 
            try ZWallet.fromPassphrase(allocator, passphrase);
            
        return BitcoinWallet{ .realid_identity = wallet };
    }
    
    /// Generate Bitcoin address from RealID
    pub fn getBitcoinAddress(self: BitcoinWallet, allocator: std.mem.Allocator) ![]u8 {
        // Use RealID public key as seed for Bitcoin key derivation
        const bitcoin_seed = self.realid_identity.master_identity.public_key.bytes;
        
        // Derive Bitcoin private key (simplified - use proper BIP32 in production)
        const bitcoin_privkey = std.crypto.hash.sha256(bitcoin_seed);
        
        // Generate Bitcoin address (simplified - implement proper Base58Check)
        const pubkey_hash = std.crypto.hash.Ripemd160.hash(bitcoin_seed);
        
        var address = try allocator.alloc(u8, 42); // "bc1" + 32 hex chars
        const written = try std.fmt.bufPrint(address, "bc1{x}", .{std.fmt.fmtSliceHexLower(&pubkey_hash)});
        return written;
    }
    
    /// Sign Bitcoin transaction
    pub fn signBitcoinTransaction(self: BitcoinWallet, tx_hash: [32]u8) !realid.RealIDSignature {
        return self.realid_identity.signTransaction(&tx_hash);
    }
};
```

### Ethereum-Style Wallet

```zig
pub const EthereumWallet = struct {
    realid_identity: ZWallet,
    
    pub fn init(allocator: std.mem.Allocator, passphrase: []const u8, device_bound: bool) !EthereumWallet {
        const wallet = if (device_bound) 
            try ZWallet.fromPassphraseWithDevice(allocator, passphrase)
        else 
            try ZWallet.fromPassphrase(allocator, passphrase);
            
        return EthereumWallet{ .realid_identity = wallet };
    }
    
    /// Generate Ethereum address from RealID
    pub fn getEthereumAddress(self: EthereumWallet, allocator: std.mem.Allocator) ![]u8 {
        // Use RealID QID as Ethereum address (20 bytes)
        const qid_bytes = self.realid_identity.qid.bytes;
        
        // Take first 20 bytes of QID for Ethereum address
        var address = try allocator.alloc(u8, 42); // "0x" + 40 hex chars
        const written = try std.fmt.bufPrint(address, "0x{x}", .{std.fmt.fmtSliceHexLower(qid_bytes[0..20])});
        return written;
    }
    
    /// Sign Ethereum transaction
    pub fn signEthereumTransaction(self: EthereumWallet, tx_data: []const u8) !realid.RealIDSignature {
        // Hash transaction data with Keccak256 (simplified)
        const tx_hash = std.crypto.hash.sha256(tx_data); // Use Keccak256 in production
        return self.realid_identity.signTransaction(&tx_hash);
    }
};
```

### Multi-Currency Wallet

```zig
pub const MultiCurrencyWallet = struct {
    realid_identity: ZWallet,
    supported_currencies: []const Currency,
    
    const Currency = enum {
        bitcoin,
        ethereum,
        litecoin,
        monero,
        ghostnet, // Your custom currency
    };
    
    pub fn init(allocator: std.mem.Allocator, passphrase: []const u8, device_bound: bool) !MultiCurrencyWallet {
        const wallet = if (device_bound) 
            try ZWallet.fromPassphraseWithDevice(allocator, passphrase)
        else 
            try ZWallet.fromPassphrase(allocator, passphrase);
            
        const currencies = &[_]Currency{ .bitcoin, .ethereum, .litecoin, .monero, .ghostnet };
        
        return MultiCurrencyWallet{ 
            .realid_identity = wallet,
            .supported_currencies = currencies,
        };
    }
    
    /// Get address for specific currency
    pub fn getAddressForCurrency(self: MultiCurrencyWallet, allocator: std.mem.Allocator, currency: Currency) ![]u8 {
        const qid_bytes = self.realid_identity.qid.bytes;
        
        return switch (currency) {
            .bitcoin => blk: {
                const pubkey_hash = std.crypto.hash.Ripemd160.hash(qid_bytes);
                var address = try allocator.alloc(u8, 42);
                const written = try std.fmt.bufPrint(address, "bc1{x}", .{std.fmt.fmtSliceHexLower(&pubkey_hash)});
                break :blk written;
            },
            .ethereum => blk: {
                var address = try allocator.alloc(u8, 42);
                const written = try std.fmt.bufPrint(address, "0x{x}", .{std.fmt.fmtSliceHexLower(qid_bytes[0..20])});
                break :blk written;
            },
            .ghostnet => blk: {
                // Use QID directly as GhostNet address
                var address = try allocator.alloc(u8, 32);
                const written = try std.fmt.bufPrint(address, "ghost:{x}", .{std.fmt.fmtSliceHexLower(qid_bytes[0..16])});
                break :blk written;
            },
            else => blk: {
                // Generic address format
                var address = try allocator.alloc(u8, 40);
                const written = try std.fmt.bufPrint(address, "{s}:{x}", .{ @tagName(currency), std.fmt.fmtSliceHexLower(qid_bytes[0..20]) });
                break :blk written;
            },
        };
    }
    
    /// Sign transaction for specific currency
    pub fn signForCurrency(self: MultiCurrencyWallet, currency: Currency, tx_data: []const u8) !realid.RealIDSignature {
        // Add currency-specific context to transaction
        var hash_input = std.ArrayList(u8).init(self.realid_identity.allocator);
        defer hash_input.deinit();
        
        try hash_input.appendSlice(@tagName(currency));
        try hash_input.appendSlice(":");
        try hash_input.appendSlice(tx_data);
        
        return self.realid_identity.signTransaction(hash_input.items);
    }
};
```

---

## 🔐 Advanced Security Features

### Hierarchical Deterministic (HD) Wallet

```zig
pub const HDWallet = struct {
    master_identity: ZWallet,
    derivation_path: []const u32,
    
    pub fn deriveChild(self: HDWallet, allocator: std.mem.Allocator, child_index: u32) !ZWallet {
        // Create derivation seed from master identity + child index
        var derivation_seed = std.ArrayList(u8).init(allocator);
        defer derivation_seed.deinit();
        
        try derivation_seed.appendSlice(&self.master_identity.master_identity.private_key.bytes);
        try derivation_seed.appendSlice(std.mem.asBytes(&child_index));
        
        // Generate child passphrase from seed
        const child_passphrase = std.crypto.hash.sha256(derivation_seed.items);
        const child_passphrase_hex = try std.fmt.allocPrint(allocator, "{x}", .{std.fmt.fmtSliceHexLower(&child_passphrase)});
        defer allocator.free(child_passphrase_hex);
        
        // Generate child wallet
        return ZWallet.fromPassphrase(allocator, child_passphrase_hex);
    }
    
    /// Derive wallet for specific purpose (BIP44-style)
    pub fn deriveForPurpose(self: HDWallet, allocator: std.mem.Allocator, purpose: enum { receiving, change, staking }) !ZWallet {
        const purpose_index = switch (purpose) {
            .receiving => 0,
            .change => 1,
            .staking => 2,
        };
        
        return self.deriveChild(allocator, purpose_index);
    }
};
```

### Multi-Signature Wallet

```zig
pub const MultiSigWallet = struct {
    participants: []ZWallet,
    required_signatures: usize,
    allocator: std.mem.Allocator,
    
    pub fn init(allocator: std.mem.Allocator, passphrases: []const []const u8, required: usize, device_bound: bool) !MultiSigWallet {
        var participants = try allocator.alloc(ZWallet, passphrases.len);
        
        for (passphrases, 0..) |passphrase, i| {
            participants[i] = if (device_bound)
                try ZWallet.fromPassphraseWithDevice(allocator, passphrase)
            else
                try ZWallet.fromPassphrase(allocator, passphrase);
        }
        
        return MultiSigWallet{
            .participants = participants,
            .required_signatures = required,
            .allocator = allocator,
        };
    }
    
    /// Sign transaction with multiple participants
    pub fn signMultiSig(self: MultiSigWallet, tx_data: []const u8, signer_indices: []const usize) ![]realid.RealIDSignature {
        if (signer_indices.len < self.required_signatures) {
            return error.InsufficientSignatures;
        }
        
        var signatures = try self.allocator.alloc(realid.RealIDSignature, signer_indices.len);
        
        for (signer_indices, 0..) |participant_idx, sig_idx| {
            if (participant_idx >= self.participants.len) {
                return error.InvalidParticipantIndex;
            }
            signatures[sig_idx] = try self.participants[participant_idx].signTransaction(tx_data);
        }
        
        return signatures;
    }
    
    /// Verify multi-signature transaction
    pub fn verifyMultiSig(self: MultiSigWallet, tx_data: []const u8, signatures: []const realid.RealIDSignature, signer_indices: []const usize) bool {
        if (signatures.len < self.required_signatures or signatures.len != signer_indices.len) {
            return false;
        }
        
        var valid_signatures: usize = 0;
        
        for (signatures, signer_indices) |signature, participant_idx| {
            if (participant_idx < self.participants.len) {
                if (self.participants[participant_idx].verifyTransaction(tx_data, signature)) {
                    valid_signatures += 1;
                }
            }
        }
        
        return valid_signatures >= self.required_signatures;
    }
    
    pub fn deinit(self: *MultiSigWallet) void {
        self.allocator.free(self.participants);
    }
};
```

---

## 🌐 Network Integration

### Wallet Server Integration

```zig
pub const WalletServer = struct {
    wallets: std.HashMap([]const u8, ZWallet),
    allocator: std.mem.Allocator,
    
    pub fn init(allocator: std.mem.Allocator) WalletServer {
        return WalletServer{
            .wallets = std.HashMap([]const u8, ZWallet).init(allocator),
            .allocator = allocator,
        };
    }
    
    /// Create or restore wallet by passphrase
    pub fn createWallet(self: *WalletServer, username: []const u8, passphrase: []const u8, device_bound: bool) ![]const u8 {
        const wallet = if (device_bound)
            try ZWallet.fromPassphraseWithDevice(self.allocator, passphrase)
        else
            try ZWallet.fromPassphrase(self.allocator, passphrase);
        
        // Use QID as wallet identifier
        var qid_buffer: [64]u8 = undefined;
        const wallet_id = try wallet.getAddress(&qid_buffer);
        const owned_id = try self.allocator.dupe(u8, wallet_id);
        
        try self.wallets.put(owned_id, wallet);
        return owned_id;
    }
    
    /// Get wallet by ID
    pub fn getWallet(self: WalletServer, wallet_id: []const u8) ?*ZWallet {
        return self.wallets.getPtr(wallet_id);
    }
    
    /// Process transaction request
    pub fn processTransaction(self: WalletServer, wallet_id: []const u8, tx_data: []const u8) !realid.RealIDSignature {
        const wallet = self.getWallet(wallet_id) orelse return error.WalletNotFound;
        return wallet.signTransaction(tx_data);
    }
};
```

---

## 📱 Example: Complete ZWallet CLI

```zig
const std = @import("std");
const realid = @import("realid");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    const stdout = std.io.getStdOut().writer();
    const stdin = std.io.getStdIn().reader();
    
    try stdout.print("🪙 ZWallet - Zero-Trust Cryptocurrency Wallet\n");
    try stdout.print("============================================\n\n");
    
    // Get passphrase from user
    try stdout.print("Enter wallet passphrase: ");
    var passphrase_buf: [256]u8 = undefined;
    const passphrase_input = try stdin.readUntilDelimiterOrEof(passphrase_buf[0..], '\n');
    const passphrase = passphrase_input orelse return error.NoInput;
    
    // Ask for device binding
    try stdout.print("Enable device binding? (y/n): ");
    var device_choice_buf: [8]u8 = undefined;
    const device_choice_input = try stdin.readUntilDelimiterOrEof(device_choice_buf[0..], '\n');
    const device_choice = device_choice_input orelse return error.NoInput;
    const device_bound = std.mem.eql(u8, device_choice, "y") or std.mem.eql(u8, device_choice, "Y");
    
    // Create wallet
    const wallet = if (device_bound)
        try ZWallet.fromPassphraseWithDevice(allocator, passphrase)
    else
        try ZWallet.fromPassphrase(allocator, passphrase);
    
    // Display wallet info
    var address_buffer: [64]u8 = undefined;
    const address = try wallet.getAddress(&address_buffer);
    
    try stdout.print("\n✅ Wallet created successfully!\n");
    try stdout.print("📍 Wallet Address: {s}\n", .{address});
    try stdout.print("🔐 Device Bound: {s}\n", .{if (device_bound) "Yes" else "No"});
    
    // Demo transaction
    const tx_data = "transfer:100:to:bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh";
    try stdout.print("\n📝 Demo Transaction: {s}\n", .{tx_data});
    
    const signature = try wallet.signTransaction(tx_data);
    try stdout.print("✍️  Transaction Signature: ", .{});
    for (signature.bytes[0..16]) |byte| {
        try stdout.print("{x:0>2}", .{byte});
    }
    try stdout.print("...\n", .{});
    
    const is_valid = wallet.verifyTransaction(tx_data, signature);
    try stdout.print("✅ Signature Valid: {s}\n", .{if (is_valid) "YES" else "NO"});
    
    try stdout.print("\n🎉 ZWallet demo completed!\n");
}
```

---

## 🚀 Production Deployment

### Security Checklist
- [ ] **Secure Passphrase Storage**: Never store passphrases in plain text
- [ ] **Device Fingerprinting**: Implement comprehensive hardware identification
- [ ] **Backup Strategy**: Document wallet recovery procedures  
- [ ] **Key Rotation**: Plan for identity refresh cycles
- [ ] **Audit Logging**: Log all wallet operations for security monitoring
- [ ] **Rate Limiting**: Implement protection against brute force attacks
- [ ] **Secure Communication**: Use TLS for all network operations

### Performance Optimization
- Cache frequently accessed wallets in memory
- Use batch operations for multiple signatures
- Implement lazy loading for wallet collections
- Pre-compute common addresses during wallet creation

### Integration Testing
```bash
# Build and test ZWallet with RealID
zig build -Doptimize=ReleaseFast
zig build test

# Run wallet functionality tests
./zig-out/bin/zwallet-test

# Security testing
./scripts/security-audit.sh
```

---

## 📚 Next Steps

1. **Study the RealID codebase** in `src/` to understand the cryptographic primitives
2. **Review INTEGRATION.md** for detailed API documentation  
3. **Check ZCRYPTO_HOWTO.md** for underlying crypto library usage
4. **Implement your specific wallet features** using the patterns above
5. **Add comprehensive testing** for your wallet implementation

For questions or contributions, please refer to the main project documentation and consider contributing improvements back to the RealID project.

**Happy building! 🚀**