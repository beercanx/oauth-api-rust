# A Rust based OAuth API
[![Rust](https://github.com/beercanx/oauth-api-rust/actions/workflows/rust.yml/badge.svg)](https://github.com/beercanx/oauth-api-rust/actions/workflows/rust.yml) 
[![CodeQL Advanced](https://github.com/beercanx/oauth-api-rust/actions/workflows/codeql.yml/badge.svg)](https://github.com/beercanx/oauth-api-rust/actions/workflows/codeql.yml) 
[![Dependabot Updates](https://github.com/beercanx/oauth-api-rust/actions/workflows/dependabot/dependabot-updates/badge.svg)](https://github.com/beercanx/oauth-api-rust/actions/workflows/dependabot/dependabot-updates) 

An exercise into how to create a HTTP service using Rust, similar to [oauth-api-go](https://github.com/beercanx/oauth-api-go) and [oauth-api](https://github.com/beercanx/oauth-api).

## Requirements
* Rust 1.92
  * https://rust-lang.org/tools/install 
* Diesel CLI 2.3.x
  * https://diesel.rs/guides/getting-started#installing-diesel-cli
* Nextest 0.9.x (optional)
  * https://nexte.st/docs/installation/pre-built-binaries
* _**(Windows only)**_ Build Tools for Visual Studio with these individual components:
  * https://rust-lang.github.io/rustup/installation/windows-msvc.html
  * _"Build Tools for Visual Studio"_ can be found via https://visualstudio.microsoft.com/downloads
  * Using that install these components:
    * MSVC Build Tools for x86/x64 (latest)
    * Windows 11 SDK (10.0.22621.0)

## Structure

```
├── src                     # Application source code
│   ├── token               # Shared token logic 
│   │   └── ...etc
│   ├── token_exchange      # Token exchange endpoint
│   │   └── ...etc
│   ├── token_introspection # Token introspection endpoint
│   │   └── ...etc
│   └── main.rs             # Application entry point
├── scripts
│   └── http                # Jetbrains HTTP Client requests, with assertions.
└── README.md
```

## Building

The standard Cargo (Rust build tool) approach
```bash
cargo build
```

## Linting

The standard rust linter, which is enforced by the GitHub Actions workflow
```bash
cargo clippy
```

## Testing

Replaced the vanilla Cargo (Rust build tool) approach with cargo-nextest: https://nexte.st
```bash
cargo nextest run
```

## Running

The standard Cargo (Rust build tool) approach
```bash
cargo run
```

### Checking its running

Hit the token exchange endpoint with a password grant _(yeah, it's deprecated; but it's a quick lazy way to start)_.
```bash
curl -v -X POST -H 'Content-Type: application/x-www-form-urlencoded' -u 'aardvark:badger' -d 'grant_type=password&scope=basic&username=aardvark&password=P%4055w0rd' http://127.0.0.1:8080/token
```

Hit the token introspection endpoint with the token just issued.
```bash
curl -v -X POST -H 'Content-Type: application/x-www-form-urlencoded' -u 'aardvark:badger' -d 'token=483d83dd-92a2-4d73-817f-8fd0e7203cb3' http://127.0.0.1:8080/introspect
```

## Reading materials
* https://docs.rs/axum/latest/axum/index.html
* https://docs.rs/axum-extra/latest/axum_extra/index.html
* https://docs.rs/axum/latest/axum/extract/index.html
* https://docs.rs/axum/latest/axum/middleware/index.html
* https://docs.rs/axum/latest/axum/error_handling/index.html
* https://docs.rs/tower/latest/tower
* https://crates.io/crates/anyhow
* https://crates.io/crates/thiserror
* https://docs.diesel.rs/2.0.x/diesel/index.html
* https://obito.fr/posts/2022/12/use-uuid-in-sqlite-database-with-rust-diesel.rs/
