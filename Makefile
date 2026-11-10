.PHONY: build test fmt lint check clean

build:
	cargo build --all-features

test:
	cargo test --all-features

fmt:
	cargo fmt --all

lint:
	cargo clippy --all-targets --all-features -- -D warnings

check: fmt lint test

clean:
	cargo clean
