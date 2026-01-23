# sa-token-rust

中文文档 | [English](README.md)

一个轻量级、高性能的 Rust 认证授权框架，灵感来自 [sa-token](https://github.com/dromara/sa-token)。

## ✨ 特性

- 🚀 **多框架支持**: Axum, Actix-web, Poem, Rocket, Warp, Salvo, Tide, Gotham, Ntex
- 🔐 **完整的认证**: 登录、登出、Token 验证、Session 管理
- 🛡️ **细粒度授权**: 基于权限和角色的访问控制
- 💾 **灵活存储**: 内存、Redis 和数据库存储后端
- 🎯 **易于使用**: 过程宏和工具类简化集成
- ⚡ **高性能**: 零拷贝设计，支持 async/await
- 🔧 **高度可配置**: Token 超时、Cookie 选项、自定义 Token 名称
- 🎧 **事件监听**: 监听登录、登出、踢出下线等认证事件
- 🔑 **JWT 支持**: 完整的 JWT (JSON Web Token) 实现，支持多种算法
- 🔒 **安全特性**: Nonce 防重放攻击、Refresh Token 刷新机制
- 🌐 **OAuth2 支持**: 完整的 OAuth2 授权码模式实现
- 🌐 **WebSocket 认证**: 安全的 WebSocket 连接认证，支持多种 Token 来源
- 👥 **在线用户管理**: 实时在线状态跟踪和消息推送
- 🔄 **分布式 Session**: 跨服务 Session 共享，适用于微服务架构
- 🎫 **SSO 单点登录**: 完整的 SSO 实现，支持票据认证和统一登出

## 📦 架构

```
sa-token-rust/
├── sa-token-core/              # 核心库（Token、Session、Manager）
│   ├── token/                  # Token 管理
│   │   ├── generator.rs        # Token 生成（UUID、Random、JWT、Hash、Timestamp、Tik）
│   │   ├── validator.rs        # Token 验证
│   │   ├── jwt.rs              # JWT 实现（HS256/384/512、RS256/384/512、ES256/384）
│   │   └── mod.rs              # Token 类型（TokenValue、TokenInfo）
│   ├── session/                # Session 管理
│   ├── permission/             # 权限和角色检查
│   ├── event/                  # 事件监听系统
│   │   └── mod.rs              # 事件总线、监听器（Login、Logout、KickOut等）
│   ├── nonce.rs                # Nonce 管理器（防重放攻击）
│   ├── refresh.rs              # Refresh Token 管理器
│   ├── oauth2.rs               # OAuth2 授权码模式
│   ├── ws.rs                   # WebSocket 认证
│   ├── online.rs               # 在线用户管理和实时推送
│   ├── distributed.rs          # 分布式 Session 管理
│   ├── sso.rs                  # SSO 单点登录（Server、Client、Ticket）
│   ├── manager.rs              # SaTokenManager（核心管理器）
│   ├── config.rs               # 配置和构建器
│   └── util.rs                 # StpUtil（工具类）
├── sa-token-adapter/           # 适配器接口（Storage、Request/Response）
├── sa-token-macro/             # 过程宏（#[sa_check_login] 等）
├── sa-token-storage-memory/    # 内存存储实现
├── sa-token-storage-redis/     # Redis 存储实现
├── sa-token-storage-database/  # 数据库存储实现（占位符）
├── sa-token-plugin-axum/       # Axum 框架集成
├── sa-token-plugin-actix-web/  # Actix-web 框架集成
├── sa-token-plugin-poem/       # Poem 框架集成
├── sa-token-plugin-rocket/     # Rocket 框架集成
├── sa-token-plugin-warp/       # Warp 框架集成
├── sa-token-plugin-salvo/      # Salvo 框架集成
├── sa-token-plugin-tide/       # Tide 框架集成
├── sa-token-plugin-gotham/     # Gotham 框架集成
├── sa-token-plugin-ntex/       # Ntex 框架集成
├── examples/                   # 示例项目
│   ├── event_listener_example.rs      # 事件监听演示
│   ├── jwt_example.rs                 # JWT 完整演示
│   ├── token_styles_example.rs        # Token 风格演示
│   ├── security_features_example.rs   # Nonce & Refresh Token 演示
│   ├── oauth2_example.rs              # OAuth2 授权流程演示
│   ├── websocket_online_example.rs    # WebSocket 认证 & 在线用户演示
│   ├── distributed_session_example.rs # 分布式 Session 演示
│   └── sso_example.rs                 # SSO 单点登录演示
└── docs/                       # 文档
    ├── JWT_GUIDE.md / JWT_GUIDE_zh-CN.md
    ├── OAUTH2_GUIDE.md / OAUTH2_GUIDE_zh-CN.md
    ├── EVENT_LISTENER.md / EVENT_LISTENER_zh-CN.md
    ├── PATH_AUTH_GUIDE.md / PATH_AUTH_GUIDE_zh-CN.md  # 路径鉴权
    ├── WEBSOCKET_AUTH.md           # WebSocket 认证（7 种语言）
    ├── ONLINE_USER_MANAGEMENT.md   # 在线用户管理（7 种语言）
    ├── DISTRIBUTED_SESSION.md      # 分布式 Session（7 种语言）
    ├── ERROR_REFERENCE.md          # 错误参考（7 种语言）
    └── StpUtil.md / StpUtil_zh-CN.md
```

### 📊 架构讨论

下面通过架构图来更直观地理解 sa-token-rust 的设计思路和组件关系：

<!-- <img src="docs/IMG_3972.JPG" alt="sa-token-rust 架构图" width="200px" height="300px" /> -->

<img src="https://sa-token.cc/big-file/contact/sa-token-rust--wx-group-qr.png" alt="sa-token-rust 微信交流群" width="200px" height="300px" />

**架构说明：**

从架构图中可以看出，sa-token-rust 采用了分层设计理念：

1. **核心层（sa-token-core）**：提供所有认证授权的核心逻辑，包括 Token 管理、Session 管理、权限控制等。这一层与具体的 Web 框架无关，保证了核心功能的复用性。

2. **适配层（sa-token-adapter）**：定义了存储和请求/响应的抽象接口，使得核心层可以适配不同的存储后端和 Web 框架。

3. **插件层（sa-token-plugin-*）**：针对不同 Web 框架的集成插件，每个插件都实现了框架特定的中间件和提取器，但对外提供统一的 API。

4. **存储层（sa-token-storage-*）**：多种存储后端实现，包括内存存储、Redis 存储和数据库存储，用户可以根据实际需求选择。

5. **工具层（sa-token-macro）**：提供过程宏，简化开发者的使用，通过注解式编程实现认证授权的声明式配置。

这种分层架构设计的优势在于：
- **高内聚低耦合**：每一层只关注自己的职责，层与层之间通过接口交互
- **易于扩展**：可以轻松添加新的框架插件或存储后端
- **框架无关**：核心功能不依赖任何 Web 框架，保证了代码的可移植性

## 🎯 核心组件

### 1. **sa-token-core**
核心认证授权逻辑：
- `SaTokenManager`: Token 和 Session 操作的主管理器
- `StpUtil`: 提供简化 API 的工具类 ([文档](docs/StpUtil_zh-CN.md))
- Token 生成、验证和刷新
- 多种 Token 风格（UUID、Random、JWT、Hash、Timestamp、Tik）
- Session 管理
- 权限和角色检查
- 事件监听系统 ([文档](docs/EVENT_LISTENER_zh-CN.md))
- JWT 支持，多种算法 ([JWT 指南](docs/JWT_GUIDE_zh-CN.md))
- 安全特性：Nonce 防重放攻击、Refresh Token 刷新机制
- OAuth2 授权码模式 ([OAuth2 指南](docs/OAUTH2_GUIDE_zh-CN.md))
- 路径鉴权 ([路径鉴权指南](docs/PATH_AUTH_GUIDE_zh-CN.md))
- WebSocket 认证 ([WebSocket 指南](docs/WEBSOCKET_AUTH.md))
- 在线用户管理和实时推送 ([在线用户指南](docs/ONLINE_USER_MANAGEMENT.md))
- 微服务分布式 Session ([分布式 Session 指南](docs/DISTRIBUTED_SESSION.md))
- SSO 单点登录 ([SSO 指南](docs/SSO_GUIDE.md#中文))

### 2. **sa-token-adapter**
框架集成的抽象层：
- `SaStorage`: Token 和 Session 的存储接口
- `SaRequest` / `SaResponse`: 请求/响应抽象

### 3. **sa-token-macro**
用于注解式认证的过程宏：
- `#[sa_check_login]`: 要求登录
- `#[sa_check_permission("user:list")]`: 检查权限 ([匹配规则](docs/PermissionMatching.md#中文))
- `#[sa_check_role("admin")]`: 检查角色
- `#[sa_check_permissions_and(...)]`: 检查多个权限（AND）
- `#[sa_check_permissions_or(...)]`: 检查多个权限（OR）
- `#[sa_ignore]`: 跳过认证

### 4. **Web 框架插件**
支持的框架：Axum, Actix-web, Poem, Rocket, Warp, Salvo, Tide, Gotham, Ntex

所有插件都提供：
- 使用 Builder 模式的状态管理
- 双重中间件（基础 + 强制登录）
- 三种提取器（必须、可选、LoginId）
- 请求/响应适配器
- 从 Header/Cookie/Query 提取 Token
- Bearer Token 支持

## 🚀 快速开始

### ⚡ 简化使用方式（推荐）

**新功能！** 只需一个依赖即可导入所有功能：

```toml
[dependencies]
# 一站式包 - 包含核心、宏和存储
sa-token-plugin-axum = "0.1.12"  # 默认：内存存储
tokio = { version = "1", features = ["full"] }
axum = "0.8"
```

**一行导入：**
```rust
use sa_token_plugin_axum::*;  // ✨ 你需要的一切！

// 现在你可以直接使用：
// - SaTokenManager, StpUtil
// - MemoryStorage, RedisStorage（通过 features）
// - 所有宏：#[sa_check_login], #[sa_check_permission]
// - JWT, OAuth2, WebSocket, 在线用户等
```

**通过 features 选择存储后端：**
```toml
# Redis 存储
sa-token-plugin-axum = { version = "0.1.12", features = ["redis"] }

# 多个存储后端
sa-token-plugin-axum = { version = "0.1.12", features = ["memory", "redis"] }

# 所有存储后端
sa-token-plugin-axum = { version = "0.1.12", features = ["full"] }
```

**可用的 features：**
- `memory`（默认）：内存存储
- `redis`：Redis 存储  
- `database`：数据库存储
- `full`：所有存储后端

**可用的插件：**
- `sa-token-plugin-axum` - Axum 框架
- `sa-token-plugin-actix-web` - Actix-web 框架
- `sa-token-plugin-poem` - Poem 框架
- `sa-token-plugin-rocket` - Rocket 框架
- `sa-token-plugin-warp` - Warp 框架

---

### 📦 传统使用方式（高级）

如果你喜欢细粒度控制，仍然可以分别导入各个包：

```toml
[dependencies]
sa-token-core = "0.1.12"
sa-token-storage-memory = "0.1.12"
sa-token-plugin-axum = "0.1.12"
tokio = { version = "1", features = ["full"] }
axum = "0.8"
```

---

### 2. 初始化 sa-token

#### 方式 A: 使用内存存储（开发环境）

**使用简化导入：**
```rust
use sa_token_plugin_axum::*;  // ✨ 一行导入
use std::sync::Arc;

#[tokio::main]
async fn main() {
    // 创建状态（StpUtil 会自动初始化）
    let state = SaTokenState::builder()
        .storage(Arc::new(MemoryStorage::new()))  // 已重新导出！
        .token_name("Authorization")
        .timeout(86400)  // 24 小时
        .build();
    
    // StpUtil 已就绪，可以直接使用！
    // 你的应用代码...
}
```

#### 方式 B: 使用 Redis 存储（生产环境）

**添加 Redis feature 到依赖：**
```toml
[dependencies]
sa-token-plugin-axum = { version = "0.1.12", features = ["redis"] }
```

**使用简化导入：**
```rust
use sa_token_plugin_axum::*;  // ✨ RedisStorage 已包含！
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 连接 Redis（带密码）
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

**方法 2: RedisConfig 结构体（推荐配置文件读取）**

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

**方法 3: Builder 构建器（最灵活）**

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

### 3. 用户登录

```rust
use sa_token_core::StpUtil;

// 用户登录
let token = StpUtil::login("user_id_10001").await?;
println!("Token: {}", token.value());

// 设置权限和角色
StpUtil::set_permissions(
    "user_id_10001",
    vec!["user:list".to_string(), "user:add".to_string()]
).await?;

StpUtil::set_roles(
    "user_id_10001",
    vec!["admin".to_string()]
).await?;
```

### 4. 检查认证（Axum 示例）

```rust
use axum::{Router, routing::get};
use sa_token_plugin_axum::{SaTokenMiddleware, LoginIdExtractor};

async fn user_info(LoginIdExtractor(login_id): LoginIdExtractor) -> String {
    format!("当前用户: {}", login_id)
}

async fn admin_panel(login_id: LoginIdExtractor) -> String {
    // 检查权限
    if !StpUtil::has_permission(&login_id.0, "admin:panel").await {
        return "无权限".to_string();
    }
    format!("欢迎管理员: {}", login_id.0)
}

let app = Router::new()
    .route("/user/info", get(user_info))
    .route("/admin/panel", get(admin_panel))
    .layer(SaTokenMiddleware::new(state));
```

### 5. 使用过程宏

```rust
use sa_token_macro::*;

#[sa_check_login]
async fn protected_route() -> &'static str {
    "此路由需要登录"
}

#[sa_check_permission("user:delete")]
async fn delete_user(user_id: String) -> &'static str {
    "用户已删除"
}

#[sa_check_role("admin")]
async fn admin_only() -> &'static str {
    "仅管理员可见内容"
}
```

### 6. 事件监听

监听登录、登出、踢出下线等认证事件：

```rust
use async_trait::async_trait;
use sa_token_core::SaTokenListener;
use std::sync::Arc;

// 创建自定义监听器
struct MyListener;

#[async_trait]
impl SaTokenListener for MyListener {
    async fn on_login(&self, login_id: &str, token: &str, login_type: &str) {
        println!("用户 {} 登录了", login_id);
        // 在这里添加你的业务逻辑：
        // - 记录到数据库
        // - 发送通知
        // - 更新统计数据
    }

    async fn on_logout(&self, login_id: &str, token: &str, login_type: &str) {
        println!("用户 {} 登出了", login_id);
    }

    async fn on_kick_out(&self, login_id: &str, token: &str, login_type: &str) {
        println!("用户 {} 被踢出下线", login_id);
    }
}

// 注册监听器
StpUtil::register_listener(Arc::new(MyListener)).await;

// 或使用内置的日志监听器
use sa_token_core::LoggingListener;
StpUtil::register_listener(Arc::new(LoggingListener)).await;

// 事件会自动触发
let token = StpUtil::login("user_123").await?; // 触发登录事件
StpUtil::logout(&token).await?;                 // 触发登出事件
StpUtil::kick_out("user_123").await?;          // 触发踢出下线事件
```

📖 **[完整事件监听文档](docs/EVENT_LISTENER_zh-CN.md)**

### 7. Token 风格

sa-token-rust 支持多种 Token 生成风格，满足不同场景需求：

```rust
use sa_token_core::SaTokenConfig;
use sa_token_core::config::TokenStyle;

let config = SaTokenConfig::builder()
    .token_style(TokenStyle::Tik)  // 选择你喜欢的风格
    .build_config();
```

#### 可用的 Token 风格

| 风格 | 长度 | 示例 | 使用场景 |
|------|------|------|----------|
| **Uuid** | 36 字符 | `550e8400-e29b-41d4-a716-446655440000` | 标准 UUID 格式，通用性强 |
| **SimpleUuid** | 32 字符 | `550e8400e29b41d4a716446655440000` | 无横杠的 UUID，更紧凑 |
| **Random32** | 32 字符 | `a3f5c9d8e2b7f4a6c1e8d3b9f2a7c5e1` | 随机十六进制字符串，安全性好 |
| **Random64** | 64 字符 | `a3f5c9d8...` | 更长的随机字符串，安全性更高 |
| **Random128** | 128 字符 | `a3f5c9d8...` | 最长随机字符串，超高安全性 |
| **Jwt** | 可变长度 | `eyJhbGc...` | 自包含令牌，带有声明信息 ([JWT指南](docs/JWT_GUIDE.md)) |
| **Hash** ⭐ | 64 字符 | `472c7dce...` | SHA256 哈希，包含用户信息，可追溯 |
| **Timestamp** ⭐ | ~30 字符 | `1760404107094_a8f4f17d88fcddb8` | 包含时间戳，易于追踪 |
| **Tik** ⭐ | 8 字符 | `GIxYHHD5` | 短小精悍，适合分享 |

⭐ = 本版本新增

#### Token 风格示例

```rust
// Uuid 风格（默认）
.token_style(TokenStyle::Uuid)
// 输出: 550e8400-e29b-41d4-a716-446655440000

// Hash 风格 - 哈希中包含用户信息
.token_style(TokenStyle::Hash)
// 输出: 472c7dceee2b3079a1ae70746f43ba99b91636292ba7811b3bc8985a1148836f

// Timestamp 风格 - 包含毫秒级时间戳
.token_style(TokenStyle::Timestamp)
// 输出: 1760404107094_a8f4f17d88fcddb8

// Tik 风格 - 短小的8位字符 token
.token_style(TokenStyle::Tik)
// 输出: GIxYHHD5

// JWT 风格 - 自包含令牌
.token_style(TokenStyle::Jwt)
.jwt_secret_key("your-secret-key")
// 输出: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

#### 如何选择 Token 风格

- **Uuid/SimpleUuid**: 标准选择，兼容性广
- **Random32/64/128**: 需要特定长度的随机 token 时
- **JWT**: 需要自包含令牌，内嵌信息时
- **Hash**: 需要可追溯到用户信息的 token 时
- **Timestamp**: 需要知道 token 创建时间时
- **Tik**: 需要短小 token 用于分享（URL、二维码等）时

运行示例查看所有 Token 风格效果：
```bash
cargo run --example token_styles_example
```

### 8. 安全特性

#### Nonce 防重放攻击

```rust
use sa_token_core::NonceManager;

let nonce_manager = NonceManager::new(storage, 300); // 5 分钟有效期

// 生成 nonce
let nonce = nonce_manager.generate();

// 验证并消费（单次使用）
nonce_manager.validate_and_consume(&nonce, "user_123").await?;

// 第二次使用将失败（检测到重放攻击）
match nonce_manager.validate_and_consume(&nonce, "user_123").await {
    Err(_) => println!("重放攻击已阻止！"),
    _ => {}
}
```

#### Refresh Token 刷新机制

```rust
use sa_token_core::RefreshTokenManager;

let refresh_manager = RefreshTokenManager::new(storage, config);

// 生成 refresh token
let refresh_token = refresh_manager.generate("user_123");
refresh_manager.store(&refresh_token, &access_token, "user_123").await?;

// 访问令牌过期时刷新
let (new_access_token, user_id) = refresh_manager
    .refresh_access_token(&refresh_token)
    .await?;
```

运行安全特性示例：
```bash
cargo run --example security_features_example
```

### 9. OAuth2 授权

完整的 OAuth2 授权码模式实现：

```rust
use sa_token_core::{OAuth2Manager, OAuth2Client};

let oauth2 = OAuth2Manager::new(storage);

// 注册 OAuth2 客户端
let client = OAuth2Client {
    client_id: "web_app_001".to_string(),
    client_secret: "secret_abc123xyz".to_string(),
    redirect_uris: vec!["http://localhost:3000/callback".to_string()],
    grant_types: vec!["authorization_code".to_string()],
    scope: vec!["read".to_string(), "write".to_string()],
};

oauth2.register_client(&client).await?;

// 生成授权码
let auth_code = oauth2.generate_authorization_code(
    "web_app_001".to_string(),
    "user_123".to_string(),
    "http://localhost:3000/callback".to_string(),
    vec!["read".to_string()],
);

oauth2.store_authorization_code(&auth_code).await?;

// 授权码换取令牌
let token = oauth2.exchange_code_for_token(
    &auth_code.code,
    "web_app_001",
    "secret_abc123xyz",
    "http://localhost:3000/callback",
).await?;

// 验证访问令牌
let token_info = oauth2.verify_access_token(&token.access_token).await?;

// 刷新令牌
let new_token = oauth2.refresh_access_token(
    token.refresh_token.as_ref().unwrap(),
    "web_app_001",
    "secret_abc123xyz",
).await?;
```

📖 **[OAuth2 完整指南](docs/OAUTH2_GUIDE_zh-CN.md)**

运行 OAuth2 示例：
```bash
cargo run --example oauth2_example
```

### 10. SSO 单点登录

完整的 SSO 实现，支持票据认证：

```rust
use sa_token_core::{SsoServer, SsoClient, SsoConfig};

// 创建 SSO Server
let sso_server = SsoServer::new(manager.clone())
    .with_ticket_timeout(300);  // 5 分钟

// 创建 SSO Client
let client = SsoClient::new(
    manager.clone(),
    "http://sso.example.com/auth".to_string(),
    "http://app1.example.com".to_string(),
);

// 配置跨域支持的 SSO
let config = SsoConfig::builder()
    .server_url("http://sso.example.com/auth")
    .ticket_timeout(300)
    .allow_cross_domain(true)
    .add_allowed_origin("http://app1.example.com".to_string())
    .build();

// 用户登录流程
let ticket = sso_server.login(
    "user_123".to_string(),
    "http://app1.example.com".to_string(),
).await?;

// 验证票据
let login_id = sso_server.validate_ticket(
    &ticket.ticket_id,
    "http://app1.example.com",
).await?;

// 创建本地会话
let token = client.login_by_ticket(login_id).await?;

// 统一登出（所有应用）
let clients = sso_server.logout("user_123").await?;
for client_url in clients {
    // 通知各客户端登出
}
```

📖 **[SSO 完整指南](docs/SSO_GUIDE.md#中文)**

运行 SSO 示例：
```bash
cargo run --example sso_example
```

## 📚 框架集成示例

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

// 初始化 Sa-Token
let sa_token_manager = conf::init_sa_token(None)
    .await
    .expect("Sa-Token 初始化失败");

// 创建 Sa-Token 状态
let sa_token_state = SaTokenState {
    manager: sa_token_manager.clone(),
};

// 创建应用状态数据
let sa_token_data = web::Data::new(sa_token_state.clone());

HttpServer::new(move || {
    App::new()
        // 注册中间件
        .wrap(Logger::default())
        .app_data(sa_token_data.clone()) // 注入 Sa-Token 到应用状态
        .wrap(SaTokenMiddleware::new(sa_token_state.clone()))
        
        // 路由
        .route("/api/login", web::post().to(login))
        .route("/api/user/info", web::get().to(user_info))
})
.bind("0.0.0.0:3000")?
.run()
.await

// 完整示例请参考 examples/actix-web-example/
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
    format!("用户: {}", login_id.0)
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
        format!("用户信息")
    });

warp::serve(routes)
    .run(([127, 0, 0, 1], 8080))
    .await;
```

## 📖 文档

### 核心文档
- [StpUtil API 参考](docs/StpUtil_zh-CN.md) - StpUtil 工具类完整指南
- [权限匹配规则](docs/PermissionMatching.md#中文) - 权限检查工作原理
- [路径鉴权](docs/PATH_AUTH_GUIDE_zh-CN.md) - 配置基于路径的鉴权
- [架构概览](docs/ARCHITECTURE.md) - 系统架构和设计
- [快速开始指南](docs/QUICK_START.md) - 快速入门

### 功能指南
- **认证与授权**
  - [事件监听指南](docs/EVENT_LISTENER_zh-CN.md) - 监听认证事件（登录、登出、踢出）
  - [JWT 指南](docs/JWT_GUIDE_zh-CN.md) - JWT 实现，支持 8 种算法
  - [OAuth2 指南](docs/OAUTH2_GUIDE_zh-CN.md) - OAuth2 授权码模式

- **实时通信与 WebSocket**
  - [WebSocket 认证](docs/WEBSOCKET_AUTH.md) - 安全的 WebSocket 连接认证（7 种语言）
  - [在线用户管理](docs/ONLINE_USER_MANAGEMENT.md) - 实时状态跟踪和推送（7 种语言）

- **分布式系统**
  - [分布式 Session](docs/DISTRIBUTED_SESSION.md) - 跨服务 Session 共享（7 种语言）
  - [SSO 单点登录](docs/SSO_GUIDE.md#中文) - 基于票据的 SSO 和统一登出（7 种语言）

- **错误处理**
  - [错误参考](docs/ERROR_REFERENCE.md) - 完整的错误类型文档（7 种语言）

### 示例代码
- [示例目录](examples/) - 所有功能的完整示例
  - `event_listener_example.rs` - 事件监听（包含 WebSocket 支持）
  - `jwt_example.rs` - JWT 生成和验证
  - `token_styles_example.rs` - 7 种 Token 生成风格
  - `security_features_example.rs` - Nonce 和 Refresh Token
  - `oauth2_example.rs` - OAuth2 授权流程
  - `websocket_online_example.rs` - WebSocket 认证和在线用户管理
  - `distributed_session_example.rs` - 分布式 Session 管理
  - `sso_example.rs` - SSO 单点登录和票据验证
  - `axum-full-example/` - 完整的 Axum 框架集成示例
  - `actix-web-example/` - 完整的 Actix-web 框架集成示例
  - `poem-full-example/` - 完整的 Poem 框架集成示例

### 多语言支持
大部分文档支持 7 种语言：
- 🇬🇧 English（英语）
- 🇨🇳 中文
- 🇹🇭 ภาษาไทย（泰语）
- 🇻🇳 Tiếng Việt（越南语）
- 🇰🇭 ភាសាខ្មែរ（高棉语）
- 🇲🇾 Bahasa Melayu（马来语）
- 🇲🇲 မြန်မာဘာသာ（缅甸语）

## 📋 版本历史

### 版本 0.1.10（当前版本）

**新增功能：**
- 🎁 **简化依赖管理**：
  - 所有插件现在支持直接基于版本的依赖（无需 workspace.dependencies）
  - 一行导入：`use sa_token_plugin_axum::*;` 包含所有需要的功能
  - 插件自动重新导出核心类型、宏和存储实现
  - 简化了示例代码的依赖结构
- 🛠️ **代码质量改进**：
  - 修复了所有插件中的模糊全局重导出警告
  - 移除了宏实现中的未使用变量
  - 改进了代码文档，添加了双语注释
  - 增强了框架插件的类型安全性
- 🔄 **框架插件增强**：
  - 为所有 Web 框架添加了 Layer 模式实现
  - 改进了 Token 提取逻辑，提供更好的错误处理
  - 通过优化上下文管理增强了中间件性能
  - 统一了所有插件的命名约定
- 🔧 **错误处理改进**：
  - 在 `error.rs` 中集中管理错误消息
  - 改进了过程宏中的错误传播
  - 更好地集成框架特定的错误类型
  - 添加了详细的错误上下文以便调试

**改进：**
- 减少了 95% 的编译时警告
- 提高了代码可读性和可维护性
- 增强了开发体验，API 设计更清晰
- 更好地集成 IDE 工具和文档
- 修复了所有示例项目以适配新的依赖结构

**改进：**
- 减少了 95% 的编译时警告
- 提高了代码可读性和可维护性
- 通过更清晰的 API 设计增强了开发者体验
- 更好地集成 IDE 工具和文档

### 版本 0.1.5

**新增功能：**
- 🎫 **SSO 单点登录**：完整的 SSO 实现，基于票据认证
  - SSO Server 用于中央认证
  - SSO Client 用于应用集成
  - 票据生成、验证和过期机制
  - 跨所有应用的统一登出
  - 跨域支持，带域名白名单
  - 服务 URL 匹配安全保护
- 🔧 **增强通用适配器**：框架集成的通用工具函数
  - `parse_cookies()`: 解析 HTTP Cookie 头
  - `parse_query_string()`: 解析 URL 查询参数，自动 URL 解码
  - `build_cookie_string()`: 构建 Set-Cookie 头字符串
  - `extract_bearer_token()`: 从 Authorization 头提取 Bearer token
  - 完整的单元测试和双语文档
- 🚀 **新增 4 个框架支持**：扩展框架生态系统
  - **Salvo (v0.73)**：现代化 Web 框架，支持 Handler 宏
    - 请求/响应适配器
    - 认证和权限中间件
  - **Tide (v0.16)**：基于 async-std 的框架
    - 请求/响应适配器
    - 支持扩展数据的中间件
  - **Gotham (v0.7)**：类型安全路由框架
    - 简化的中间件（由于复杂的 State 系统）
  - **Ntex (v2.8)**：高性能框架
    - 完整的 Service trait 中间件

**改进：**
- 通过通用工具减少 70% 的代码重复
- 所有 9 个框架统一接口设计
- TokenValue 转换提升类型安全
- 针对各框架优化错误处理
- 框架支持从 5 个扩展到 9 个（+80%）

### 版本 0.1.3
  
**新增功能：**
- 🌐 **WebSocket 认证**：安全的 WebSocket 连接认证
  - 多种 Token 来源（header、query、自定义）
  - WsAuthManager 用于连接管理
  - 与事件系统集成
- 👥 **在线用户管理**：实时用户状态跟踪
  - OnlineManager 跟踪活跃用户
  - 向在线用户推送消息
  - 支持自定义消息类型
- 🔄 **分布式 Session**：跨服务会话共享
  - 服务间认证
  - 分布式会话存储
  - 服务凭证管理
- 🎨 **事件系统增强**：改进的事件监听器注册
  - Builder 模式集成事件监听器
  - 同步注册（无需 `.await`）
  - 自动初始化 StpUtil
- 📚 **文档改进**：
  - 主要功能支持 7 种语言
  - 多语言合并文档格式
  - 全面的代码注释（双语）
  - 代码流程逻辑文档

**改进：**
- 通过插件重新导出简化导入
- 通过 Builder 模式实现一行初始化
- 使用集中式错误定义改进错误处理
- 增强 API 文档

### 版本 0.1.2

**新增功能：**
- 🔑 **JWT 支持**：完整的 JWT 实现
  - 8 种算法（HS256/384/512, RS256/384/512, ES256/384）
  - 自定义声明支持
  - Token 刷新机制
- 🔒 **安全特性**：
  - Nonce 管理器防止重放攻击
  - Refresh Token 刷新机制
- 🌐 **OAuth2 支持**：完整的 OAuth2 授权码模式
  - 客户端注册和管理
  - 授权码生成和交换
  - 访问令牌和刷新令牌处理
  - Token 撤销
- 🎨 **新 Token 风格**：Hash、Timestamp、Tik 风格
- 🎧 **事件监听系统**：监听认证事件
  - Login、Logout、KickOut 事件
  - 自定义监听器支持
  - 内置 LoggingListener

**改进：**
- 错误处理重构为集中式 `SaTokenError`
- 多语言错误文档
- 增强的权限和角色检查

### 版本 0.1.1

**新增功能：**
- 🚀 **多框架支持**：Axum、Actix-web、Poem、Rocket、Warp、Salvo、Tide、Gotham、Ntex
- 🔐 **核心认证**：登录、登出、Token 验证
- 🛡️ **授权**：基于权限和角色的访问控制
- 💾 **存储后端**：内存和 Redis 存储
- 🎯 **过程宏**：`#[sa_check_login]`、`#[sa_check_permission]`、`#[sa_check_role]`
- 📦 **灵活架构**：核心库与框架适配器分离

**核心组件：**
- `SaTokenManager`：Token 和会话管理
- `StpUtil`：简化的工具 API
- 多种 Token 生成风格（UUID、Random32/64/128）
- Session 管理
- 存储抽象层

## 🔧 高级用法

### 自定义存储

实现 `SaStorage` trait 来使用自己的存储后端：

```rust
use sa_token_adapter::storage::SaStorage;
use async_trait::async_trait;

pub struct CustomStorage;

#[async_trait]
impl SaStorage for CustomStorage {
    async fn get(&self, key: &str) -> Option<String> {
        // 你的实现
    }
    
    async fn set(&self, key: &str, value: String, timeout: Option<i64>) {
        // 你的实现
    }
    
    // ... 其他方法
}
```

### Token 配置

```rust
let state = SaTokenState::builder()
    .storage(Arc::new(MemoryStorage::new()))
    .token_name("X-Token")           // 自定义 Token 名称
    .timeout(7200)                    // Token 超时（秒）
    .active_timeout(1800)             // 活动超时（秒）
    .build();
```

## 🤝 贡献

欢迎贡献！请随时提交 issues 和 pull requests。

## 📄 许可证

本项目采用以下任一许可证：

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT License ([LICENSE-MIT](LICENSE-MIT))

由你选择。

## 👨‍💻 作者

**金书记**

## 🙏 致谢

本项目受 [sa-token](https://github.com/dromara/sa-token) Java 框架启发。

