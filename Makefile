.PHONY: build test fmt fmt-check lint doc check clean release

VERSION ?=
PRERELEASE_FLAG := $(if $(findstring -,$(VERSION)),--prerelease,)

build:
	cargo build --all-features

test:
	cargo test --all-features

fmt:
	cargo fmt --all

fmt-check:
	cargo fmt --all -- --check

lint:
	cargo clippy --all-targets --all-features -- -D warnings

doc:
	RUSTDOCFLAGS="-D warnings" cargo doc --all-features --no-deps

check: fmt lint test doc

clean:
	cargo clean

release:
	@test -n "$(VERSION)" || { echo "VERSION is required, for example: make release VERSION=0.1.1" >&2; exit 1; }
	@printf '%s' "$(VERSION)" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$$' || { echo "VERSION '$(VERSION)' is not a valid version, expected x.y.z or x.y.z-<suffix>" >&2; exit 1; }
	@test -z "$$(git status --porcelain)" || { echo "the working tree has uncommitted changes" >&2; exit 1; }
	@if git rev-parse -q --verify "refs/tags/v$(VERSION)" >/dev/null; then echo "the tag v$(VERSION) already exists locally" >&2; exit 1; fi
	@remote_tags=$$(git ls-remote --tags origin "v$(VERSION)") || { echo "cannot reach origin to look for the tag v$(VERSION)" >&2; exit 1; }; \
		test -z "$$remote_tags" || { echo "the tag v$(VERSION) already exists on origin" >&2; exit 1; }
	@status=$$(curl -s -o /dev/null -w '%{http_code}' -H 'User-Agent: badbots-release' "https://crates.io/api/v1/crates/badbots/$(VERSION)" || true); \
		case "$$status" in \
			404) ;; \
			200) echo "crates.io already carries badbots $(VERSION)" >&2; exit 1 ;; \
			*) echo "cannot tell whether crates.io carries badbots $(VERSION) (HTTP $$status)" >&2; exit 1 ;; \
		esac
	@$(MAKE) fmt-check lint test doc
	@git commit --allow-empty -m "chore(release): $(VERSION)"
	@git tag -a "v$(VERSION)" -m "badbots $(VERSION)"
	@git push --atomic origin HEAD:main "v$(VERSION)"
	@gh release create "v$(VERSION)" --generate-notes --verify-tag $(PRERELEASE_FLAG)
