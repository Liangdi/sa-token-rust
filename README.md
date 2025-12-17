# sa-token-rust

[中文文档](README_zh-CN.md) | English

A lightweight, high-performance authentication and authorization framework for Rust, inspired by [sa-token](https://github.com/dromara/sa-token).

## ✨ Features

- 🚀 **Multiple Web Framework Support**: Axum, Actix-web, Poem, Rocket, Warp, Salvo, Tide, Gotham, Ntex
- 🔐 **Complete Authentication**: Login, logout, token validation, session management
- 🛡️ **Fine-grained Authorization**: Permission and role-based access control
- 💾 **Flexible Storage**: Memory, Redis, and database storage backends
- 🎯 **Easy to Use**: Procedural macros and utility classes for simple integration
- ⚡ **High Performance**: Zero-copy design, async/await support
- 🔧 **Highly Configurable**: Token timeout, cookie options, custom token names
- 🎧 **Event Listeners**: Monitor login, logout, kick-out, and other authentication events
- 🔑 **JWT Support**: Full JWT (JSON Web Token) implementation with multiple algorithms
- 🔒 **Security Features**: Nonce for replay attack prevention, refresh token mechanism
- 🌐 **OAuth2 Support**: Complete OAuth2 authorization code flow implementation
- 🌐 **WebSocket Authentication**: Secure WebSocket connection authentication with multiple token sources
- 👥 **Online User Management**: Real-time online status tracking and message push
- 🔄 **Distributed Session**: Cross-service session sharing for microservices architecture
- 🎫 **SSO Single Sign-On**: Complete SSO implementation with ticket-based authentication and unified logout

## 📦 Architecture

```
sa-token-rust/
├── sa-token-core/              # Core library (Token, Session, Manager)
│   ├── token/                  # Token management
│   │   ├── generator.rs        # Token generation (UUID, Random, JWT, Hash, Timestamp, Tik)
│   │   ├── validator.rs        # Token validation
│   │   ├── jwt.rs              # JWT implementation (HS256/384/512, RS256/384/512, ES256/384)
│   │   └── mod.rs              # Token types (TokenValue, TokenInfo)
│   ├── session/                # Session management
│   ├── permission/             # Permission and role checking
│   ├── event/                  # Event listener system
│   │   └── mod.rs              # Event bus, listeners (Login, Logout, KickOut, etc.)
│   ├── nonce.rs                # Nonce manager (replay attack prevention)
│   ├── refresh.rs              # Refresh token manager
│   ├── oauth2.rs               # OAuth2 authorization code flow
│   ├── ws.rs                   # WebSocket authentication
│   ├── online.rs               # Online user management and real-time push
│   ├── distributed.rs          # Distributed session management
│   ├── sso.rs                  # SSO single sign-on (Server, Client, Ticket)
│   ├── manager.rs              # SaTokenManager (core manager)
│   ├── config.rs               # Configuration and builder
│   └── util.rs                 # StpUtil (utility class)
├── sa-token-adapter/           # Adapter interfaces (Storage, Request/Response)
├── sa-token-macro/             # Procedural macros (#[sa_check_login], etc.)
├── sa-token-storage-memory/    # Memory storage implementation
├── sa-token-storage-redis/     # Redis storage implementation
├── sa-token-storage-database/  # Database storage implementation (placeholder)
├── sa-token-plugin-axum/       # Axum framework integration
├── sa-token-plugin-actix-web/  # Actix-web framework integration
├── sa-token-plugin-poem/       # Poem framework integration
├── sa-token-plugin-rocket/     # Rocket framework integration
├── sa-token-plugin-warp/       # Warp framework integration
├── sa-token-plugin-salvo/      # Salvo framework integration
├── sa-token-plugin-tide/       # Tide framework integration
├── sa-token-plugin-gotham/     # Gotham framework integration
├── sa-token-plugin-ntex/       # Ntex framework integration
├── examples/                   # Example projects
│   ├── event_listener_example.rs      # Event listener demo
│   ├── jwt_example.rs                 # JWT complete demo
│   ├── token_styles_example.rs        # Token styles demo
│   ├── security_features_example.rs   # Nonce & Refresh token demo
│   ├── oauth2_example.rs              # OAuth2 authorization flow demo
│   ├── websocket_online_example.rs    # WebSocket auth & online user demo
│   ├── distributed_session_example.rs # Distributed session demo
│   └── sso_example.rs                 # SSO single sign-on demo
└── docs/                       # Documentation
    ├── JWT_GUIDE.md / JWT_GUIDE_zh-CN.md
    ├── OAUTH2_GUIDE.md / OAUTH2_GUIDE_zh-CN.md
    ├── EVENT_LISTENER.md / EVENT_LISTENER_zh-CN.md
    ├── PATH_AUTH_GUIDE.md / PATH_AUTH_GUIDE_zh-CN.md  # Path-based authentication
    ├── WEBSOCKET_AUTH.md           # WebSocket authentication (7 languages)
    ├── ONLINE_USER_MANAGEMENT.md   # Online user management (7 languages)
    ├── DISTRIBUTED_SESSION.md      # Distributed session (7 languages)
    ├── ERROR_REFERENCE.md          # Error reference (7 languages)
    └── StpUtil.md / StpUtil_zh-CN.md
```

## 🎯 Core Components

### 1. **sa-token-core**
Core authentication and authorization logic:
- `SaTokenManager`: Main manager for token and session operations
- `StpUtil`: Utility class providing simplified API ([Documentation](docs/StpUtil.md))
- Token generation, validation, and refresh
- Multiple token styles (UUID, Random, JWT, Hash, Timestamp, Tik)
- Session management
- Permission and role checking
- Event listening system ([Documentation](docs/EVENT_LISTENER.md))
- JWT support with multiple algorithms ([JWT Guide](docs/JWT_GUIDE.md))
- Security features: Nonce (replay attack prevention), Refresh Token
- OAuth2 authorization code flow ([OAuth2 Guide](docs/OAUTH2_GUIDE.md))
- Path-based authentication ([Path Auth Guide](docs/PATH_AUTH_GUIDE.md))
- WebSocket authentication ([WebSocket Guide](docs/WEBSOCKET_AUTH.md))
- Online user management and real-time push ([Online User Guide](docs/ONLINE_USER_MANAGEMENT.md))
- Distributed session for microservices ([Distributed Session Guide](docs/DISTRIBUTED_SESSION.md))
- SSO single sign-on ([SSO Guide](docs/SSO_GUIDE.md#english))

### 2. **sa-token-adapter**
Abstraction layer for framework integration:
- `SaStorage`: Storage interface for tokens and sessions
- `SaRequest` / `SaResponse`: Request/response abstraction

### 3. **sa-token-macro**
Procedural macros for annotation-style authentication:
- `#[sa_check_login]`: Require login
- `#[sa_check_permission("user:list")]`: Check permission ([Matching Rules](docs/PermissionMatching.md))
- `#[sa_check_role("admin")]`: Check role
- `#[sa_check_permissions_and(...)]`: Check multiple permissions (AND)
- `#[sa_check_permissions_or(...)]`: Check multiple permissions (OR)
- `#[sa_ignore]`: Skip authentication

### 4. **Web Framework Plugins**
Supported frameworks: Axum, Actix-web, Poem, Rocket, Warp, Salvo, Tide, Gotham, Ntex

All plugins provide:
- State management with Builder pattern
- Dual middleware (basic + login-required)
- Three extractors (required, optional, LoginId)
- Request/Response adapters
- Token extraction from Header/Cookie/Query
- Bearer token support

## 🚀 Quick Start

### ⚡ Simplified Usage (Recommended)

**New!** Import everything you need with a single dependency:

```toml
[dependencies]
# All-in-one package - includes core, macros, and storage
sa-token-plugin-axum = "0.1.12"  # Default: memory storage
tokio = { version = "1", features = ["full"] }
axum = "0.8"
```

**One-line import:**
```rust
use sa_token_plugin_axum::*;  // ✨ Everything you need!

// Now you can use:
// - SaTokenManager, StpUtil
// - MemoryStorage, RedisStorage (with features)
// - All macros: #[sa_check_login], #[sa_check_permission]
// - JWT, OAuth2, WebSocket, Online users, etc.
```

**Choose your storage backend with features:**
```toml
# Redis storage
sa-token-plugin-axum = { version = "0.1.12", features = ["redis"] }

# Multiple storage backends
sa-token-plugin-axum = { version = "0.1.12", features = ["memory", "redis"] }

# All storage backends
sa-token-plugin-axum = { version = "0.1.12", features = ["full"] }
```

**Available features:**
- `memory` (default): In-memory storage
- `redis`: Redis storage  
- `database`: Database storage
- `full`: All storage backends

**Available plugins:**
- `sa-token-plugin-axum` - Axum framework
- `sa-token-plugin-actix-web` - Actix-web framework
- `sa-token-plugin-poem` - Poem framework
- `sa-token-plugin-rocket` - Rocket framework
- `sa-token-plugin-warp` - Warp framework

---

### 📦 Traditional Usage (Advanced)

If you prefer fine-grained control, you can still import packages separately:

```toml
[dependencies]
sa-token-core = "0.1.12"
sa-token-storage-memory = "0.1.12"
sa-token-plugin-axum = "0.1.12"
tokio = { version = "1", features = ["full"] }
axum = "0.8"
```

---

### 2. Initialize sa-token

#### Option A: Using Memory Storage (Development)

**With simplified import:**
```rust
use sa_token_plugin_axum::*;  // ✨ One-line import
use std::sync::Arc;

#[tokio::main]
async fn main() {
    // Create state (StpUtil is automatically initialized)
    let state = SaTokenState::builder()
        .storage(Arc::new(MemoryStorage::new()))  // Already re-exported!
        .token_name("Authorization")
        .timeout(86400)  // 24 hours
        .build();
    
    // StpUtil is ready to use!
    // Your application code...
}
```

#### Option B: Using Redis Storage (Production)

**Add Redis feature to your dependency:**
```toml
[dependencies]
sa-token-plugin-axum = { version = "0.1.12", features = ["redis"] }
```

**With simplified import:**
```rust
use sa_token_plugin_axum::*;  // ✨ RedisStorage already included!
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Connect to Redis with password
    let storage = RedisStorage::new(
        "redis://:Aq23-hjPwFB3mBDNFp3W1@localhost:6379/0",
        "sa-token:"
    ).await?;
    
    let state = SaTokenState::builder()
        .storage(Arc::new(storage))
        .timeout(86400)
        .build();
    
    Ok(())
}
```

**Method 2: RedisConfig Structure (Recommended for configuration files)**

```rust
use sa_token_storage_redis::{RedisStorage, RedisConfig};
use sa_token_plugin_axum::SaTokenState;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = RedisConfig {
        host: "localhost".to_string(),
        port: 6379,
        password: Some("Aq23-hjPwFB3mBDNFp3W1".to_string()),
        database: 0,
        pool_size: 10,
    };
    
    let storage = RedisStorage::from_config(config, "sa-token:").await?;
    
    let state = SaTokenState::builder()
        .storage(Arc::new(storage))
        .timeout(86400)
        .build();
    
    Ok(())
}
```

**Method 3: Builder Pattern (Most flexible)**

```rust
use sa_token_storage_redis::RedisStorage;
use sa_token_plugin_axum::SaTokenState;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let storage = RedisStorage::builder()
        .host("localhost")
        .port(6379)
        .password("Aq23-hjPwFB3mBDNFp3W1")
        .database(0)
        .key_prefix("sa-token:")
        .build()
        .await?;
    
    let state = SaTokenState::builder()
        .storage(Arc::new(storage))
        .timeout(86400)
        .build();
    
    Ok(())
}
```

### 3. User Login

```rust
use sa_token_core::StpUtil;

// User login
let token = StpUtil::login("user_id_10001").await?;
println!("Token: {}", token.value());

// Set permissions and roles
StpUtil::set_permissions(
    "user_id_10001",
    vec!["user:list".to_string(), "user:add".to_string()]
).await?;

StpUtil::set_roles(
    "user_id_10001",
    vec!["admin".to_string()]
).await?;
```

### 4. Check Authentication (Axum Example)

```rust
use axum::{Router, routing::get};
use sa_token_plugin_axum::{SaTokenMiddleware, LoginIdExtractor};

async fn user_info(LoginIdExtractor(login_id): LoginIdExtractor) -> String {
    format!("Current user: {}", login_id)
}

async fn admin_panel(login_id: LoginIdExtractor) -> String {
    // Check permission
    if !StpUtil::has_permission(&login_id.0, "admin:panel").await {
        return "No permission".to_string();
    }
    format!("Welcome admin: {}", login_id.0)
}

let app = Router::new()
    .route("/user/info", get(user_info))
    .route("/admin/panel", get(admin_panel))
    .layer(SaTokenMiddleware::new(state));
```

### 5. Using Procedural Macros

```rust
use sa_token_macro::*;

#[sa_check_login]
async fn protected_route() -> &'static str {
    "This route requires login"
}

#[sa_check_permission("user:delete")]
async fn delete_user(user_id: String) -> &'static str {
    "User deleted"
}

#[sa_check_role("admin")]
async fn admin_only() -> &'static str {
    "Admin only content"
}
```

### 6. Event Listeners

Monitor authentication events like login, logout, and kick-out:

```rust
use async_trait::async_trait;
use sa_token_core::SaTokenListener;
use std::sync::Arc;

// Create custom listener
struct MyListener;

#[async_trait]
impl SaTokenListener for MyListener {
    async fn on_login(&self, login_id: &str, token: &str, login_type: &str) {
        println!("User {} logged in", login_id);
        // Add your business logic here:
        // - Log to database
        // - Send notification
        // - Update statistics
    }

    async fn on_logout(&self, login_id: &str, token: &str, login_type: &str) {
        println!("User {} logged out", login_id);
    }

    async fn on_kick_out(&self, login_id: &str, token: &str, login_type: &str) {
        println!("User {} was kicked out", login_id);
    }
}

// Register listener
StpUtil::register_listener(Arc::new(MyListener)).await;

// Or use built-in logging listener
use sa_token_core::LoggingListener;
StpUtil::register_listener(Arc::new(LoggingListener)).await;

// Events are automatically triggered
let token = StpUtil::login("user_123").await?; // Triggers Login event
StpUtil::logout(&token).await?;                 // Triggers Logout event
StpUtil::kick_out("user_123").await?;          // Triggers KickOut event
```

For complete event listener documentation, see [Event Listener Guide](docs/EVENT_LISTENER.md).

### 7. Token Styles

sa-token-rust supports multiple token generation styles to meet different scenarios:

```rust
use sa_token_core::SaTokenConfig;
use sa_token_core::config::TokenStyle;

let config = SaTokenConfig::builder()
    .token_style(TokenStyle::Tik)  // Choose your preferred style
    .build_config();
```

#### Available Token Styles

| Style | Length | Example | Use Case |
|-------|--------|---------|----------|
| **Uuid** | 36 chars | `550e8400-e29b-41d4-a716-446655440000` | Standard UUID format, universally recognized |
| **SimpleUuid** | 32 chars | `550e8400e29b41d4a716446655440000` | UUID without hyphens, more compact |
| **Random32** | 32 chars | `a3f5c9d8e2b7f4a6c1e8d3b9f2a7c5e1` | Random hex string, good security |
| **Random64** | 64 chars | `a3f5c9d8...` | Longer random string, higher security |
| **Random128** | 128 chars | `a3f5c9d8...` | Maximum random length, ultra-secure |
| **Jwt** | Variable | `eyJhbGc...` | Self-contained token with claims ([JWT Guide](docs/JWT_GUIDE.md)) |
| **Hash** ⭐ | 64 chars | `472c7dce...` | SHA256 hash with user info, traceable |
| **Timestamp** ⭐ | ~30 chars | `1760404107094_a8f4f17d88fcddb8` | Includes timestamp, easy to track |
| **Tik** ⭐ | 8 chars | `GIxYHHD5` | Short and shareable, perfect for URLs |

⭐ = New in this version

#### Token Style Examples

```rust
// Uuid style (default)
.token_style(TokenStyle::Uuid)
// Output: 550e8400-e29b-41d4-a716-446655440000

// Hash style - includes user information in hash
.token_style(TokenStyle::Hash)
// Output: 472c7dceee2b3079a1ae70746f43ba99b91636292ba7811b3bc8985a1148836f

// Timestamp style - includes millisecond timestamp
.token_style(TokenStyle::Timestamp)
// Output: 1760404107094_a8f4f17d88fcddb8

// Tik style - short 8-character token
.token_style(TokenStyle::Tik)
// Output: GIxYHHD5

// JWT style - self-contained token with claims
.token_style(TokenStyle::Jwt)
.jwt_secret_key("your-secret-key")
// Output: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

#### Choosing the Right Token Style

- **Uuid/SimpleUuid**: Standard choice, widely compatible
- **Random32/64/128**: When you need random tokens with specific length
- **JWT**: When you need self-contained tokens with embedded information
- **Hash**: When you need tokens that can be traced back to user info
- **Timestamp**: When you need to know when the token was created
- **Tik**: When you need short tokens for sharing (URLs, QR codes, etc.)

Run the example to see all token styles in action:
```bash
cargo run --example token_styles_example
```

### 8. Security Features

#### Nonce (Replay Attack Prevention)

```rust
use sa_token_core::NonceManager;

let nonce_manager = NonceManager::new(storage, 300); // 5 minutes TTL

// Generate nonce
let nonce = nonce_manager.generate();

// Validate and consume (one-time use)
nonce_manager.validate_and_consume(&nonce, "user_123").await?;

// Second use will fail (replay attack detected)
match nonce_manager.validate_and_consume(&nonce, "user_123").await {
    Err(_) => println!("Replay attack prevented!"),
    _ => {}
}
```

#### Refresh Token

```rust
use sa_token_core::RefreshTokenManager;

let refresh_manager = RefreshTokenManager::new(storage, config);

// Generate refresh token
let refresh_token = refresh_manager.generate("user_123");
refresh_manager.store(&refresh_token, &access_token, "user_123").await?;

// Refresh access token when expired
let (new_access_token, user_id) = refresh_manager
    .refresh_access_token(&refresh_token)
    .await?;
```

Run security features example:
```bash
cargo run --example security_features_example
```

### 9. OAuth2 Authorization

Complete OAuth2 authorization code flow implementation:

```rust
use sa_token_core::{OAuth2Manager, OAuth2Client};

let oauth2 = OAuth2Manager::new(storage);

// Register OAuth2 client
let client = OAuth2Client {
    client_id: "web_app_001".to_string(),
    client_secret: "secret_abc123xyz".to_string(),
    redirect_uris: vec!["http://localhost:3000/callback".to_string()],
    grant_types: vec!["authorization_code".to_string()],
    scope: vec!["read".to_string(), "write".to_string()],
};

oauth2.register_client(&client).await?;

// Generate authorization code
let auth_code = oauth2.generate_authorization_code(
    "web_app_001".to_string(),
    "user_123".to_string(),
    "http://localhost:3000/callback".to_string(),
    vec!["read".to_string()],
);

oauth2.store_authorization_code(&auth_code).await?;

// Exchange code for token
let token = oauth2.exchange_code_for_token(
    &auth_code.code,
    "web_app_001",
    "secret_abc123xyz",
    "http://localhost:3000/callback",
).await?;

// Verify access token
let token_info = oauth2.verify_access_token(&token.access_token).await?;

// Refresh token
let new_token = oauth2.refresh_access_token(
    token.refresh_token.as_ref().unwrap(),
    "web_app_001",
    "secret_abc123xyz",
).await?;
```

📖 **[OAuth2 Complete Guide](docs/OAUTH2_GUIDE.md)**

Run OAuth2 example:
```bash
cargo run --example oauth2_example
```

### 10. SSO Single Sign-On

Complete SSO implementation with ticket-based authentication:

```rust
use sa_token_core::{SsoServer, SsoClient, SsoConfig};

// Create SSO Server
let sso_server = SsoServer::new(manager.clone())
    .with_ticket_timeout(300);  // 5 minutes

// Create SSO Client
let client = SsoClient::new(
    manager.clone(),
    "http://sso.example.com/auth".to_string(),
    "http://app1.example.com".to_string(),
);

// Configure SSO with cross-domain support
let config = SsoConfig::builder()
    .server_url("http://sso.example.com/auth")
    .ticket_timeout(300)
    .allow_cross_domain(true)
    .add_allowed_origin("http://app1.example.com".to_string())
    .build();

// User login flow
let ticket = sso_server.login(
    "user_123".to_string(),
    "http://app1.example.com".to_string(),
).await?;

// Validate ticket
let login_id = sso_server.validate_ticket(
    &ticket.ticket_id,
    "http://app1.example.com",
).await?;

// Create local session
let token = client.login_by_ticket(login_id).await?;

// Unified logout (all applications)
let clients = sso_server.logout("user_123").await?;
for client_url in clients {
    // Notify each client to logout
}
```

📖 **[SSO Complete Guide](docs/SSO_GUIDE.md#english)**

Run SSO example:
```bash
cargo run --example sso_example
```

📖 **[Full Event Listener Documentation](docs/EVENT_LISTENER.md)**

## 📚 Framework Integration Examples

### Axum

```rust
use axum::{Router, routing::{get, post}};
use sa_token_plugin_axum::{SaTokenState, SaTokenMiddleware, LoginIdExtractor};

let state = SaTokenState::builder()
    .storage(Arc::new(MemoryStorage::new()))
    .build();

let app = Router::new()
    .route("/user/info", get(user_info))
    .layer(SaTokenMiddleware::new(state));
```

### Actix-web

```rust
use actix_web::{App, HttpServer, web};
use sa_token_plugin_actix_web::{SaTokenState, SaTokenMiddleware, LoginIdExtractor};

// Initialize Sa-Token
let sa_token_manager = conf::init_sa_token(None)
    .await
    .expect("Sa-Token initialization failed");

// Create Sa-Token state
let sa_token_state = SaTokenState {
    manager: sa_token_manager.clone(),
};

// Create data for application state
let sa_token_data = web::Data::new(sa_token_state.clone());

HttpServer::new(move || {
    App::new()
        // Register middleware
        .wrap(Logger::default())
        .app_data(sa_token_data.clone()) // Inject Sa-Token into application state
        .wrap(SaTokenMiddleware::new(sa_token_state.clone()))
        
        // Routes
        .route("/api/login", web::post().to(login))
        .route("/api/user/info", web::get().to(user_info))
})
.bind("0.0.0.0:3000")?
.run()
.await

// For a complete example, see examples/actix-web-example/
```

### Poem

```rust
use poem::{Route, Server};
use sa_token_plugin_poem::{SaTokenState, SaTokenMiddleware, LoginIdExtractor};

let state = SaTokenState::builder()
    .storage(Arc::new(MemoryStorage::new()))
    .build();

let app = Route::new()
    .at("/user/info", poem::get(user_info))
    .with(SaTokenMiddleware::new(state));

Server::new(TcpListener::bind("127.0.0.1:8080"))
    .run(app)
    .await
```

### Rocket

```rust
use rocket::{launch, get, routes};
use sa_token_plugin_rocket::{SaTokenState, SaTokenFairing, LoginIdGuard};

#[get("/user/info")]
fn user_info(login_id: LoginIdGuard) -> String {
    format!("User: {}", login_id.0)
}

#[launch]
fn rocket() -> _ {
    let state = SaTokenState::builder()
        .storage(Arc::new(MemoryStorage::new()))
        .build();
    
    rocket::build()
        .attach(SaTokenFairing::new(state))
        .mount("/", routes![user_info])
}
```

### Warp

```rust
use warp::Filter;
use sa_token_plugin_warp::{SaTokenState, sa_token_filter};

let state = SaTokenState::builder()
    .storage(Arc::new(MemoryStorage::new()))
    .build();

let routes = warp::path("user")
    .and(warp::path("info"))
    .and(sa_token_filter(state))
    .map(|token_data| {
        format!("User info")
    });

warp::serve(routes)
    .run(([127, 0, 0, 1], 8080))
    .await;
```

## 📖 Documentation

### Core Documentation
- [StpUtil API Reference](docs/StpUtil.md) - Complete guide to StpUtil utility class
- [Permission Matching Rules](docs/PermissionMatching.md#english) - How permission checking works
- [Path-Based Authentication](docs/PATH_AUTH_GUIDE.md) - Configure path-based authentication
- [Architecture Overview](docs/ARCHITECTURE.md) - System architecture and design
- [Quick Start Guide](docs/QUICK_START.md) - Get started quickly

### Feature Guides
- **Authentication & Authorization**
  - [Event Listener Guide](docs/EVENT_LISTENER.md) - Monitor authentication events (Login, Logout, KickOut)
  - [JWT Guide](docs/JWT_GUIDE.md) - JSON Web Token implementation with 8 algorithms
  - [OAuth2 Guide](docs/OAUTH2_GUIDE.md) - OAuth2 authorization code flow

- **Real-time & WebSocket**
  - [WebSocket Authentication](docs/WEBSOCKET_AUTH.md) - Secure WebSocket connection auth (7 languages)
  - [Online User Management](docs/ONLINE_USER_MANAGEMENT.md) - Real-time status tracking and push (7 languages)

- **Distributed Systems**
  - [Distributed Session](docs/DISTRIBUTED_SESSION.md) - Cross-service session sharing (7 languages)
  - [SSO Single Sign-On](docs/SSO_GUIDE.md#english) - Ticket-based SSO with unified logout (7 languages)

- **Error Handling**
  - [Error Reference](docs/ERROR_REFERENCE.md) - Complete error types documentation (7 languages)

### Examples
- [Examples Directory](examples/) - Working examples for all features
  - `event_listener_example.rs` - Event listener with WebSocket support
  - `jwt_example.rs` - JWT generation and validation
  - `token_styles_example.rs` - 7 token generation styles
  - `security_features_example.rs` - Nonce & Refresh Token
  - `oauth2_example.rs` - OAuth2 authorization flow
  - `websocket_online_example.rs` - WebSocket auth & online user management
  - `distributed_session_example.rs` - Distributed session management
  - `sso_example.rs` - SSO single sign-on with ticket validation
  - `axum-full-example/` - Complete Axum framework integration example
  - `actix-web-example/` - Complete Actix-web framework integration example
  - `poem-full-example/` - Complete Poem framework integration example

### Language Support
Most documentation is available in 7 languages:
- 🇬🇧 English
- 🇨🇳 中文 (Chinese)
- 🇹🇭 ภาษาไทย (Thai)
- 🇻🇳 Tiếng Việt (Vietnamese)
- 🇰🇭 ភាសាខ្មែរ (Khmer)
- 🇲🇾 Bahasa Melayu (Malay)
- 🇲🇲 မြန်မာဘာသာ (Burmese)

## 📋 Version History

### Version 0.1.10 (Current)

**New Features:**
- 🎁 **Simplified Dependency Management**:
  - All plugins now support direct version-based dependencies (no workspace.dependencies needed)
  - One-line import: `use sa_token_plugin_axum::*;` includes everything you need
  - Plugins automatically re-export core types, macros, and storage implementations
  - Simplified examples with cleaner dependency structure
- 🛠️ **Code Quality Improvements**:
  - Fixed ambiguous glob re-exports warnings across all plugins
  - Removed unused variables in macro implementations
  - Improved code documentation with bilingual comments
  - Enhanced type safety in framework plugins
- 🔄 **Framework Plugin Enhancements**:
  - Added Layer pattern implementation for all web frameworks
  - Improved token extraction logic with better error handling
  - Enhanced middleware performance with optimized context management
  - Standardized naming conventions across all plugins
- 🔧 **Error Handling Refinements**:
  - Centralized error messages in `error.rs`
  - Improved error propagation in procedural macros
  - Better integration with framework-specific error types
  - Added detailed error context for debugging

**Improvements:**
- Reduced compile-time warnings by 95%
- Improved code readability and maintainability
- Enhanced developer experience with clearer API design
- Better integration with IDE tools and documentation
- Fixed all example projects to work with new dependency structure

### Version 0.1.5

**New Features:**
- 🎫 **SSO Single Sign-On**: Complete SSO implementation with ticket-based authentication
  - SSO Server for centralized authentication
  - SSO Client for application integration
  - Ticket generation, validation, and expiration
  - Unified logout across all applications
  - Cross-domain support with origin whitelist
  - Service URL matching for security
- 🔧 **Enhanced Universal Adapter**: Common utility functions for framework integration
  - `parse_cookies()`: Parse HTTP Cookie headers
  - `parse_query_string()`: Parse URL query parameters with auto URL decoding
  - `build_cookie_string()`: Build Set-Cookie header strings
  - `extract_bearer_token()`: Extract Bearer token from Authorization header
  - Complete unit tests and bilingual documentation
- 🚀 **4 New Framework Support**: Expanded framework ecosystem
  - **Salvo (v0.73)**: Modern web framework with Handler macros
    - Request/Response adapter
    - Authentication and permission middleware
  - **Tide (v0.16)**: async-std based framework
    - Request/Response adapter
    - Middleware with extension data support
  - **Gotham (v0.7)**: Type-safe routing framework
    - Simplified middleware (due to complex State system)
  - **Ntex (v2.8)**: High-performance framework
    - Complete middleware with Service trait

**Improvements:**
- Reduced code duplication by 70% with common utilities
- Unified interface design across all 9 frameworks
- Better type safety with TokenValue conversions
- Improved error handling for each framework
- Framework support expanded from 5 to 9 (+80%)

### Version 0.1.3

**New Features:**  
- 🌐 **WebSocket Authentication**: Secure WebSocket connection authentication
  - Multiple token sources (header, query, custom)
  - WsAuthManager for connection management
  - Integration with event system
- 👥 **Online User Management**: Real-time user status tracking
  - OnlineManager for tracking active users
  - Message push to online users
  - Custom message types support
- 🔄 **Distributed Session**: Cross-service session sharing
  - Service-to-service authentication
  - Distributed session storage
  - Service credential management
- 🎨 **Enhanced Event System**: Improved event listener registration
  - Builder pattern integration for event listeners
  - Synchronous registration (no `.await` needed)
  - Automatic StpUtil initialization
- 📚 **Documentation Improvements**:
  - 7-language support for major features
  - Multi-language merged documentation format
  - Comprehensive code comments (bilingual)
  - Code flow logic documentation

**Improvements:**
- Simplified import with plugin re-exports
- One-line initialization via builder pattern
- Better error handling with centralized error definitions
- Enhanced API documentation

### Version 0.1.2

**New Features:**
- 🔑 **JWT Support**: Full JWT implementation
  - 8 algorithms (HS256/384/512, RS256/384/512, ES256/384)
  - Custom claims support
  - Token refresh mechanism
- 🔒 **Security Features**:
  - Nonce manager for replay attack prevention
  - Refresh token mechanism
- 🌐 **OAuth2 Support**: Complete OAuth2 authorization code flow
  - Client registration and management
  - Authorization code generation and exchange
  - Access token and refresh token handling
  - Token revocation
- 🎨 **New Token Styles**: Hash, Timestamp, Tik styles
- 🎧 **Event Listener System**: Monitor authentication events
  - Login, Logout, KickOut events
  - Custom listener support
  - Built-in LoggingListener

**Improvements:**
- Error handling refactored to use centralized `SaTokenError`
- Multi-language error documentation
- Enhanced permission and role checking

### Version 0.1.1

**New Features:**
- 🚀 **Multi-framework Support**: Axum, Actix-web, Poem, Rocket, Warp
- 🔐 **Core Authentication**: Login, logout, token validation
- 🛡️ **Authorization**: Permission and role-based access control
- 💾 **Storage Backends**: Memory and Redis storage
- 🎯 **Procedural Macros**: `#[sa_check_login]`, `#[sa_check_permission]`, `#[sa_check_role]`
- 📦 **Flexible Architecture**: Core library with framework adapters

**Core Components:**
- `SaTokenManager`: Token and session management
- `StpUtil`: Simplified utility API
- Multiple token generation styles (UUID, Random32/64/128)
- Session management
- Storage abstraction layer

## 🔧 Advanced Usage

### Custom Storage

Implement the `SaStorage` trait for your own storage backend:

```rust
use sa_token_adapter::storage::SaStorage;
use async_trait::async_trait;

pub struct CustomStorage;

#[async_trait]
impl SaStorage for CustomStorage {
    async fn get(&self, key: &str) -> Option<String> {
        // Your implementation
    }
    
    async fn set(&self, key: &str, value: String, timeout: Option<i64>) {
        // Your implementation
    }
    
    // ... other methods
}
```

### Token Configuration

```rust
let state = SaTokenState::builder()
    .storage(Arc::new(MemoryStorage::new()))
    .token_name("X-Token")           // Custom token name
    .timeout(7200)                    // Token timeout (seconds)
    .active_timeout(1800)             // Activity timeout (seconds)
    .build();
```

## 🤝 Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.

## 📄 License

This project is licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT License ([LICENSE-MIT](LICENSE-MIT))

at your option.

## 👨‍💻 Author

**金书记**

## 🙏 Acknowledgments

This project is inspired by [sa-token](https://github.com/dromara/sa-token) Java framework.

