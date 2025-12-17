// Author: 金书记
//
//! # sa-token-plugin-actix-web
//! 
//! Actix-web框架集成插件 - 一站式认证授权解决方案
//! 
//! ## 快速开始
//! 
//! 只需要导入这一个包，即可使用所有功能：
//! 
//! ```toml
//! [dependencies]
//! sa-token-plugin-actix-web = "0.1.3"  # 默认使用内存存储
//! # 或者使用 Redis 存储
//! sa-token-plugin-actix-web = { version = "0.1.3", features = ["redis"] }
//! ```
//! 
//! ## 使用示例
//! 
//! ```rust,ignore
//! use sa_token_plugin_actix_web::*;
//! 
//! // 1. 初始化（使用内存存储）
//! let state = SaTokenState::builder()
//!     .storage(Arc::new(MemoryStorage::new()))  // 已重新导出
//!     .timeout(7200)
//!     .build();
//! 
//! // 2. 登录
//! let token = state.manager().login("user123").await?;
//! 
//! // 3. 使用宏检查权限
//! #[sa_check_login]
//! async fn user_info() -> impl Responder {
//!     "User info"
//! }
//! 
//! #[sa_check_permission("admin")]
//! async fn admin_panel() -> impl Responder {
//!     "Admin panel"
//! }
//! ```

pub mod middleware;
pub mod extractor;
pub mod adapter;
pub mod layer;

pub use middleware::{SaCheckLoginMiddleware, SaTokenMiddleware};
pub use layer::SaTokenLayer;
pub use extractor::{SaTokenExtractor, OptionalSaTokenExtractor, LoginIdExtractor};
pub use adapter::{ActixRequestAdapter, ActixResponseAdapter};

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

use std::sync::Arc;
use actix_web::web::Data;

/// Actix-web应用数据
pub type SaTokenData = Data<SaTokenState>;

/// 应用状态
#[derive(Clone)]
pub struct SaTokenState {
    pub manager: Arc<SaTokenManager>,
}

impl SaTokenState {
    /// 创建状态构建器
    pub fn builder() -> SaTokenStateBuilder {
        SaTokenStateBuilder::new()
    }
}

/// 状态构建器
#[derive(Default)]
pub struct SaTokenStateBuilder {
    config_builder: sa_token_core::config::SaTokenConfigBuilder,
}

impl SaTokenStateBuilder {
    pub fn new() -> Self {
        Self::default()
    }
    
    pub fn storage(mut self, storage: Arc<dyn SaStorage>) -> Self {
        self.config_builder = self.config_builder.storage(storage);
        self
    }
    
    pub fn token_name(mut self, name: impl Into<String>) -> Self {
        self.config_builder = self.config_builder.token_name(name);
        self
    }
    
    pub fn timeout(mut self, timeout: i64) -> Self {
        self.config_builder = self.config_builder.timeout(timeout);
        self
    }
    
    pub fn active_timeout(mut self, timeout: i64) -> Self {
        self.config_builder = self.config_builder.active_timeout(timeout);
        self
    }
    
    /// 设置是否开启自动续签
    pub fn auto_renew(mut self, enabled: bool) -> Self {
        self.config_builder = self.config_builder.auto_renew(enabled);
        self
    }
    
    pub fn is_concurrent(mut self, concurrent: bool) -> Self {
        self.config_builder = self.config_builder.is_concurrent(concurrent);
        self
    }
    
    pub fn is_share(mut self, share: bool) -> Self {
        self.config_builder = self.config_builder.is_share(share);
        self
    }
    
    /// 设置 Token 风格
    pub fn token_style(mut self, style: sa_token_core::config::TokenStyle) -> Self {
        self.config_builder = self.config_builder.token_style(style);
        self
    }
    
    pub fn token_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.config_builder = self.config_builder.token_prefix(prefix);
        self
    }
    
    pub fn jwt_secret_key(mut self, key: impl Into<String>) -> Self {
        self.config_builder = self.config_builder.jwt_secret_key(key);
        self
    }
    
    pub fn build(self) -> Data<SaTokenState> {
        let manager = self.config_builder.build();
                
        Data::new(SaTokenState {
            manager: Arc::new(manager),
        })
    }
}

