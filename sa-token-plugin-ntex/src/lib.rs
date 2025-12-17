// Author: 金书记
//
// 中文 | English
// Ntex 框架集成 | Ntex Framework Integration
//
//! # sa-token-plugin-ntex
//! 
//! 为 Ntex 框架提供 sa-token 认证和授权支持
//! Provides sa-token authentication and authorization support for Ntex framework
//! 
//! ## 特性 | Features
//! 
//! - ✨ 一行导入所有功能 | One-line import for all functionalities
//! - 🔧 支持多种存储后端 | Support for multiple storage backends
//! - 🚀 简化的中间件集成 | Simplified middleware integration
//! - 📦 包含核心、宏、存储 | Includes core, macros, and storage
//! 
//! ## 快速开始 | Quick Start
//! 
//! ```toml
//! [dependencies]
//! sa-token-plugin-ntex = "0.1.5"
//! ```
//! 
//! ```rust,ignore
//! use sa_token_plugin_ntex::*;
//! use std::sync::Arc;
//! 
//! #[ntex::main]
//! async fn main() -> std::io::Result<()> {
//!     let storage = Arc::new(MemoryStorage::new());
//!     let state = SaTokenState::builder()
//!         .storage(storage)
//!         .timeout(7200)
//!         .build();
//!     
//!     ntex::web::HttpServer::new(move || {
//!         ntex::web::App::new()
//!             // 基础 token 提取中间件
//!             .wrap(SaTokenMiddleware::new(state.clone()))
//!             .route("/login", ntex::web::post().to(login_handler))
//!             .service(
//!                 ntex::web::scope("/api")
//!                     // 需要登录的路由
//!                     .wrap(SaCheckLoginMiddleware::new(state.clone()))
//!                     .route("/user", ntex::web::get().to(user_handler))
//!                     .service(
//!                         ntex::web::scope("/admin")
//!                             // 需要管理员权限的路由
//!                             .wrap(SaCheckPermissionMiddleware::new(state.clone(), "admin"))
//!                             .route("/users", ntex::web::get().to(admin_users_handler))
//!                     )
//!             )
//!     })
//!     .bind("127.0.0.1:8080")?
//!     .run()
//!     .await
//! }
//! ```

pub mod adapter;
pub mod extractor;
pub mod middleware;
pub mod layer;
pub mod state;

pub use sa_token_core::{self, prelude::*};
pub use sa_token_adapter::{self, storage::SaStorage, framework::FrameworkAdapter};
pub use sa_token_macro::*;

// 重新导出存储实现（通过 feature 控制）
// Re-export storage implementations (controlled by features)
#[cfg(feature = "memory")]
pub use sa_token_storage_memory::*;

#[cfg(feature = "redis")]
pub use sa_token_storage_redis::*;

#[cfg(feature = "database")]
pub use sa_token_storage_database::*;

// 重新导出本模块的适配器 | Re-export adapters from this module
pub use adapter::*;
pub use extractor::*;
pub use middleware::*;
pub use layer::SaTokenLayer;
pub use state::{SaTokenState, SaTokenStateBuilder};

