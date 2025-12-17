# sa-token-rust Documentation

[中文文档](./README_zh-CN.md) | English

Welcome to **sa-token-rust** documentation! All documentation is available in both English and Chinese (中文).

> 💡 **New!** [Simplified Usage Guide](../README.md#-simplified-usage-recommended) - Get started with just one dependency!

---

## 📚 Documentation Index

### 🚀 Getting Started

| Document | Description |
|----------|-------------|
| [Main README](../README.md) | Complete project overview and quick start |
| [Simplified Usage](../README.md#-simplified-usage-recommended) | One-line import, all features included |
| [Architecture Overview](../README.md#-architecture) | Project structure and design |

---

### 📖 Core Documentation

| Document | English | 中文 | Description |
|----------|---------|------|-------------|
| **StpUtil API Reference** | [StpUtil.md](./StpUtil.md) | [StpUtil_zh-CN.md](./StpUtil_zh-CN.md) | Complete guide to the StpUtil utility class |
| **Permission Matching Rules** | [PermissionMatching.md](./PermissionMatching.md#english) | [PermissionMatching.md](./PermissionMatching.md#中文) | Permission checking and wildcard matching |

---

### 🎯 Feature Guides

#### Authentication & Authorization

| Feature | English | 中文 | Description |
|---------|---------|------|-------------|
| **Event Listeners** | [EVENT_LISTENER.md](./EVENT_LISTENER.md) | [EVENT_LISTENER_zh-CN.md](./EVENT_LISTENER_zh-CN.md) | Monitor login, logout, and kick-out events |
| **Event Listener Quick Start** | [QUICKSTART.md](./EVENT_LISTENER_QUICKSTART.md) | [QUICKSTART_zh-CN.md](./EVENT_LISTENER_QUICKSTART_zh-CN.md) | Get started with event listeners in 5 minutes |
| **JWT Guide** | [JWT_GUIDE.md](./JWT_GUIDE.md) | [JWT_GUIDE_zh-CN.md](./JWT_GUIDE_zh-CN.md) | Complete JWT implementation (8 algorithms) |
| **OAuth2 Guide** | [OAUTH2_GUIDE.md](./OAUTH2_GUIDE.md) | [OAUTH2_GUIDE_zh-CN.md](./OAUTH2_GUIDE_zh-CN.md) | OAuth2 authorization code flow |

#### Real-time & WebSocket

| Feature | Multi-language Support | Description |
|---------|------------------------|-------------|
| **WebSocket Authentication** | [WEBSOCKET_AUTH.md](./WEBSOCKET_AUTH.md) | 🌍 7 languages: EN, 中文, ไทย, Tiếng Việt, ខ្មែរ, Melayu, မြန်မာ |
| **Online User Management** | [ONLINE_USER_MANAGEMENT.md](./ONLINE_USER_MANAGEMENT.md) | Track online users and push real-time messages |

#### Distributed Systems

| Feature | Multi-language Support | Description |
|---------|------------------------|-------------|
| **Distributed Session** | [DISTRIBUTED_SESSION.md](./DISTRIBUTED_SESSION.md) | Cross-service session sharing for microservices |
| **SSO Single Sign-On** | [SSO_GUIDE.md](./SSO_GUIDE.md#english) | Ticket-based SSO with unified logout (7 languages) |

#### Error Handling

| Feature | Multi-language Support | Description |
|---------|------------------------|-------------|
| **Error Reference** | [ERROR_REFERENCE.md](./ERROR_REFERENCE.md) | Complete error code reference (32 types, 7 languages) |

---

### 💻 Code Examples

All examples are located in the [`examples/`](../examples/) directory:

| Example | Description |
|---------|-------------|
| `event_listener_example.rs` | Event listeners with custom handlers |
| `jwt_example.rs` | JWT generation, validation, and refresh |
| `token_styles_example.rs` | All 7 token generation styles |
| `security_features_example.rs` | Nonce (replay attack prevention) & Refresh token |
| `oauth2_example.rs` | Complete OAuth2 authorization flow |
| `websocket_online_example.rs` | WebSocket auth + online user tracking |
| `distributed_session_example.rs` | Distributed session for microservices |

**Run examples:**
```bash
# Basic examples
cargo run --example event_listener_example
cargo run --example jwt_example

# WebSocket + Online users
cargo run --example websocket_online_example

# Distributed session
cargo run --example distributed_session_example
```

---

### 🔧 Framework Integration

| Framework | Plugin Package | Status |
|-----------|---------------|--------|
| **Axum** | `sa-token-plugin-axum` | ✅ Stable |
| **Actix-web** | `sa-token-plugin-actix-web` | ✅ Stable |
| **Poem** | `sa-token-plugin-poem` | ✅ Stable |
| **Rocket** | `sa-token-plugin-rocket` | ✅ Stable |
| **Warp** | `sa-token-plugin-warp` | ✅ Stable |

**Quick Start with Any Framework:**

```toml
[dependencies]
# All-in-one package (choose your framework)
sa-token-plugin-axum = "0.1.12"  # or actix-web, poem, rocket, warp
```

```rust
use sa_token_plugin_axum::*;  // ✨ Everything included!
```

See [Main README - Simplified Usage](../README.md#-simplified-usage-recommended) for details.

---

### 🌍 Language Support

**Bilingual Documentation (English + 中文):**
- StpUtil API Reference
- Event Listeners
- JWT Guide
- OAuth2 Guide
- Permission Matching

**Multi-language Documentation (7 languages):**
- WebSocket Authentication
- Online User Management
- Distributed Session
- SSO Single Sign-On
- Error Reference

**Supported Languages:**
- 🇬🇧 English
- 🇨🇳 中文 (Chinese)
- 🇹🇭 ภาษาไทย (Thai)
- 🇻🇳 Tiếng Việt (Vietnamese)
- 🇰🇭 ភាសាខ្មែរ (Khmer)
- 🇲🇾 Bahasa Melayu (Malay)
- 🇲🇲 မြန်မာဘာသာ (Burmese)

---

## 🎯 Feature Overview

### Core Features

- **Authentication**: Login, logout, token validation, session management
- **Authorization**: Permission and role-based access control with wildcards
- **Event System**: Listen to login, logout, kick-out, and custom events
- **Token Styles**: UUID, Random, JWT, Hash, Timestamp, Tik (7 options)

### Advanced Features

- **JWT Support**: 8 algorithms (HS256/384/512, RS256/384/512, ES256/384)
- **OAuth2**: Complete authorization code flow implementation
- **Security**: Nonce (replay attack prevention), Refresh token mechanism
- **WebSocket**: Authenticate WebSocket connections with multiple token sources
- **Online Users**: Real-time tracking and message push
- **Distributed Session**: Cross-service session sharing for microservices

### Storage Options

- **Memory** (default): In-memory storage for development
- **Redis**: Production-ready Redis backend
- **Database**: Custom database storage (extensible)

**Easy switch with features:**
```toml
sa-token-plugin-axum = { version = "0.1.12", features = ["redis"] }
```

---

## 🔍 Quick Search

**Looking for:**

- **Getting started?** → [Main README](../README.md) → [Simplified Usage](../README.md#-simplified-usage-recommended)
- **Authentication basics?** → [StpUtil API Reference](./StpUtil.md)
- **Event monitoring?** → [Event Listener Guide](./EVENT_LISTENER.md)
- **JWT tokens?** → [JWT Guide](./JWT_GUIDE.md)
- **OAuth2?** → [OAuth2 Guide](./OAUTH2_GUIDE.md)
- **WebSocket auth?** → [WebSocket Authentication](./WEBSOCKET_AUTH.md)
- **Real-time features?** → [Online User Management](./ONLINE_USER_MANAGEMENT.md)
- **Microservices?** → [Distributed Session](./DISTRIBUTED_SESSION.md)
- **Single Sign-On?** → [SSO Guide](./SSO_GUIDE.md#english)
- **Error codes?** → [Error Reference](./ERROR_REFERENCE.md)
- **Code examples?** → [Examples Directory](../examples/)

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit:
- 🐛 Bug reports
- 💡 Feature requests
- 📖 Documentation improvements
- 🔧 Pull requests

See [CONTRIBUTING.md](../CONTRIBUTING.md) for guidelines.

---

## 📄 License

This project is dual-licensed under:

- **Apache License, Version 2.0** ([LICENSE-APACHE](../LICENSE-APACHE))
- **MIT License** ([LICENSE-MIT](../LICENSE-MIT))

You may choose either license at your option.

---

## 📞 Support

- 📚 **Documentation**: You're here!
- 💬 **Issues**: [GitHub Issues](https://github.com/your-repo/sa-token-rust/issues)
- 🌟 **Star us**: If you find this project helpful, give it a ⭐ on GitHub!

---

**Made with ❤️ by the sa-token community**

