# iam-rust-auth

The **auth** microservice of the IAM platform, built in Rust (Tonic/Axum).
Independently built, tested, versioned and deployed. Shared code comes from
[iam-rust-proto](https://github.com/malvinpratama/iam-rust-proto) and
[iam-rust-common](https://github.com/malvinpratama/iam-rust-common); orchestration,
compose and docs live in the umbrella repo
[iam-rust](https://github.com/malvinpratama/iam-rust).

```bash
make build && make test     # compile + unit tests
make docker                 # build the container image
```

Requires the Rust toolchain + `protobuf-compiler` (for the proto build script).
