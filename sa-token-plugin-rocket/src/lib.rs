// Author: 金书记
//
//! # sa-token-plugin-rocket
//! 
//! Rocket框架集成插件 - 一站式认证授权解决方案
//! 
//! ## 快速开始
//! 
//! 只需要导入这一个包，即可使用所有功能：
//! 
//! ```toml
//! [dependencies]
//! sa-token-plugin-rocket = "0.1.3"  # 默认使用内存存储
//! # 或者使用 Redis 存储
//! sa-token-plugin-rocket = { version = "0.1.3", features = ["redis"] }
//! ```
//! 
//! ## 使用示例
//! 
//! ```rust,ignore
//! use rocket::{State, get};
//! use sa_token_plugin_rocket::*;  // 一次性导入所有功能
//! use std::sync::Arc;
//! 
//! // 用户信息接口 - 需要登录
//! #[get("/user/info")]
//! async fn user_info(token: SaTokenGuard) -> String {
//!     format!("User ID: {}", token.token().as_str())
//! }
//! 
//! // 管理员接口 - 需要权限
//! #[get("/admin/users")]
//! async fn admin_users(login_id: LoginIdGuard) -> String {
//!     format!("Admin: {}", login_id.login_id())
//! }
//! 
//! #[rocket::main]
//! async fn main() {
//!     // 1. 初始化（使用内存存储，已重新导出）
//!     let state = SaTokenState::builder()
//!         .storage(Arc::new(MemoryStorage::new()))
//!         .timeout(7200)
//!         .build();
//!     
//!     // 2. 创建 Rocket 实例
//!     rocket::build()
//!         // 基础中间件 - 提取并验证 token
//!         .attach(SaTokenLayer::new(state.clone()))
//!         // 登录检查中间件 - 应用于 /user 路径
//!         .attach(SaCheckLoginFairing::new(state.clone()))
//!         // 权限检查中间件 - 应用于 /admin 路径
//!         .attach(SaCheckPermissionFairing::new(state.clone(), "admin"))
//!         .manage(state)
//!         .mount("/", routes![user_info, admin_users])
//!         .launch()
//!         .await
//!         .unwrap();
//! }
//! ```

pub mod middleware;
pub mod extractor;
pub mod adapter;
pub mod layer;
pub mod state;

// ============================================================================
// Rocket 框架集成（本插件特有）
// ============================================================================
pub use middleware::{SaTokenFairing, SaCheckLoginFairing, SaCheckPermissionFairing, SaCheckRoleFairing};
pub use layer::SaTokenLayer;
pub use extractor::{SaTokenGuard, OptionalSaTokenGuard, LoginIdGuard};
pub use adapter::{RocketRequestAdapter, RocketResponseAdapter};

pub use sa_token_core::{self, prelude::*};
pub use sa_token_adapter::{self, storage::SaStorage, framework::FrameworkAdapter};
pub use sa_token_macro::*;

// ============================================================================
// 重新导出存储实现（根据 feature 条件编译）
// ============================================================================

/// 内存存储（默认启用）
#[cfg(feature = "memory")]
pub use sa_token_storage_memory::MemoryStorage;

/// Redis 存储
#[cfg(feature = "redis")]
pub use sa_token_storage_redis::RedisStorage;

/// 数据库存储
#[cfg(feature = "database")]
pub use sa_token_storage_database::DatabaseStorage;

/// 重新导出 SaTokenState 和 SaTokenStateBuilder
pub use state::{SaTokenState, SaTokenStateBuilder};
