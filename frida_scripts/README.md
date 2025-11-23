# Frida Scripts for AndroSleuth

This directory contains custom Frida hooks for dynamic analysis of Android applications.

## 📋 Available Hooks (3 scripts)

### 1. crypto_hooks.js - Cryptography Monitoring
- Cipher operations (AES, DES, RSA, etc.)
- Hashing (MD5, SHA1, SHA256, etc.)
- Secret key generation
- Base64 encoding/decoding

### 2. network_hooks.js - Network Monitoring
- HTTP/HTTPS requests
- OkHttp client
- WebView URL loading
- Socket connections
- DNS resolution

### 3. file_hooks.js - File System Monitoring
- File read/write operations
- SharedPreferences access
- SQLite database queries
- ContentProvider access (contacts, SMS, etc.)

## �� Usage

All `.js` files in this directory are automatically loaded when using `--frida`:

```bash
poetry run androsleuth -a sample.apk --frida --duration 60
```

For detailed setup instructions, see: **DYNAMIC_ANALYSIS.md**

---
**Last Updated**: 2025-11-23  
**Hooks**: crypto_hooks.js, network_hooks.js, file_hooks.js  
**Frida Version**: 17.5.1+
