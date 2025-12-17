# sa-token-plugin-rocket

Rocket framework integration for sa-token-rust.

## Features

- 🚀 **Rocket-native**: Built for Rocket 0.5
- 🎯 **Fairing Support**: Easy middleware integration
- 🔧 **Request Guards**: Type-safe authentication
- 🛡️ **Complete**: Full auth features

## Installation

```toml
[dependencies]
sa-token-plugin-rocket = { version = "0.1.12", features = ["redis"] }
rocket = "0.5"
```

## Quick Start

```rust
#[macro_use] extern crate rocket;

use rocket::State;
use sa_token_plugin_rocket::{SaTokenState, SaTokenFairing};
use sa_token_storage_memory::MemoryStorage;
use std::sync::Arc;

#[get("/user/info")]
fn user_info(login_id: LoginIdGuard) -> String {
    format!("User: {}", login_id.0)
}

#[launch]
fn rocket() -> _ {
    let state = SaTokenState::builder()
        .storage(Arc::new(MemoryStorage::new()))
        .timeout(7200)
        .build();
    
    rocket::build()
        .attach(SaTokenFairing)
        .manage(state)
        .mount("/", routes![user_info])
}
```

## Version History

### 0.1.12
- ✨ Added path-based authentication support for fine-grained access control
- 🔧 Optimized middleware implementation, reduced code duplication

### 0.1.11
- Initial release with basic features

## Author

**金书记**

## License

Licensed under either of Apache-2.0 or MIT.
