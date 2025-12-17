// Author: 金书记
//
// 中文 | English
// Gotham 框架集成 | Gotham Framework Integration
//
//! # sa-token-plugin-gotham
//! 
//! 为 Gotham 框架提供 sa-token 认证和授权支持
//! Provides sa-token authentication and authorization support for Gotham framework
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
//! sa-token-plugin-gotham = "0.1.5"
//! ```
//! 
//! ```rust,ignore
//! use sa_token_plugin_gotham::*;
//! use gotham::router::Router;
//! use gotham::pipeline::{new_pipeline, single_pipeline};
//! use std::sync::Arc;
//! 
//! #[tokio::main]
//! async fn main() {
//!     let storage = Arc::new(MemoryStorage::new());
//!     let state = SaTokenState::builder()
//!         .storage(storage)
//!         .timeout(7200)
//!         .build();
//!     
//!     // 方式1：使用基础中间件 + 手动检查
//!     let (chain, pipelines) = single_pipeline(
//!         new_pipeline()
//!             .add(SaTokenMiddleware::new(state.clone()))
//!             .build()
//!     );
//!     
//!     // 方式2：使用登录检查中间件
//!     let (chain, pipelines) = single_pipeline(
//!         new_pipeline()
//!             .add(SaCheckLoginMiddleware::new(state.clone()))
//!             .build()
//!     );
//!     
//!     // 方式3：使用权限检查中间件
//!     let (chain, pipelines) = single_pipeline(
//!         new_pipeline()
//!             .add(SaCheckPermissionMiddleware::new(state.clone(), "admin"))
//!             .build()
//!     );
//!     
//!     let router = Router::new(chain, pipelines, |route| {
//!         route.get("/api/user").to(user_handler);
//!         route.get("/api/admin").to(admin_handler);
//!     });
//!     
//!     let addr = "127.0.0.1:8080";
//!     gotham::start(addr, || Ok(router));
//! }
//! ```

pub mod adapter;
pub mod extractor;
pub mod middleware;
pub mod layer;
pub mod state;
pub mod wrapper;

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
pub use wrapper::{TokenValueWrapper, LoginIdWrapper};

