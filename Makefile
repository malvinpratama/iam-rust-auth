IMAGE ?= ghcr.io/malvinpratama/iam-rust-authatest
build:   ; cargo build --release
test:    ; cargo test
clippy:  ; cargo clippy
docker:  ; docker build -t $(IMAGE) .
