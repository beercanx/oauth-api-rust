# A Rust based OAuth API
An exercise into how to create a HTTP service using Rust, similar to [oauth-api-go](https://github.com/beercanx/oauth-api-go) and [oauth-api](https://github.com/beercanx/oauth-api).

## Requirements
* Rust 1.92
  * https://rust-lang.org/tools/install 
* _**(Windows only)**_ Build Tools for Visual Studio with these individual components:
  * https://rust-lang.github.io/rustup/installation/windows-msvc.html
  * _"Build Tools for Visual Studio"_ can be found via https://visualstudio.microsoft.com/downloads
  * Using that install these components:
    * MSVC Build Tools for x86/x64 (latest)
    * Windows 11 SDK (10.0.22621.0)

## Structure

```
├── src             # Application source code 
│   ├── one
│   │   └── ...etc
│   ├── two
│   │   └── ...etc
│   └── main.rs     # Application entry point
├── scripts
│   └── http        # Jetbrains HTTP Client requests, with assertions.
└── README.md
```

## Building

The standard Cargo (Rust build tool) approach
```bash
cargo build
```

## Testing

The standard Cargo (Rust build tool) approach
```bash
cargo test
```

## Running

The standard Cargo (Rust build tool) approach
```bash
cargo run
```

### Checking its running

Hit the token exchange endpoint with a password grant _(yeah its deprecated; but it's a quick lazy way to start)_.
```bash
curl -vvv -X POST -H 'Content-Type: application/x-www-form-urlencoded' -u 'aardvark:badger' -d 'grant_type=password&scope=basic&username=aardvark&password=P%4055w0rd' http://127.0.0.1:8080/token
```

## Reading materials
* https://docs.rs/axum/latest/axum/index.html
* https://docs.rs/axum-extra/latest/axum_extra/index.html
* https://docs.rs/axum/latest/axum/extract/index.html
* https://docs.rs/axum/latest/axum/middleware/index.html
* https://docs.rs/axum/latest/axum/error_handling/index.html
* https://docs.rs/tower/latest/tower
