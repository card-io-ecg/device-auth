device-auth
===========

Device pairing with a one-time code, and requests signed by the device's own P-256 key.

A device generates a key pair and registers its public key with a pairing code issued by the server.
Each later request carries an `ES256` JWT bound to the request method, path, and a per-route counter,
so a captured request cannot be replayed. The server holds no secret that can sign as a device.

| Crate | Side | Target |
|---|---|---|
| `device-auth-core` | both | `no_std`, no `alloc` |
| `device-auth-firmware` | device | `no_std`, no `alloc` |
| `device-auth-server` | server | `std` |

[PROTOCOL.md](PROTOCOL.md) is the normative wire format.

The crates are not on crates.io yet. Depend on this repository pinned by `rev`:

```toml
device-auth-firmware = { git = "https://github.com/card-io-ecg/device-auth.git", rev = "…" }
```

The minimum supported Rust version is 1.98.

This project is experimental. The wire format may change without notice.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the
work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any
additional terms or conditions.
