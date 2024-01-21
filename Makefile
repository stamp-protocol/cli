.PHONY: all clean release doc build run test test-panic test-st macros

# non-versioned include
VARS ?= vars.mk
-include $(VARS)

override CARGO_BUILD_ARGS += --features "$(FEATURES)" --color=always

all: build

run: build
	cargo run $(CARGO_BUILD_ARGS)

build:
	cargo build $(CARGO_BUILD_ARGS)

release: override CARGO_BUILD_ARGS += --release
release: build

doc:
	cargo doc

test-release: override CARGO_BUILD_ARGS += --release
test-release:
	cargo test $(TEST) $(CARGO_BUILD_ARGS) -- --nocapture

test:
	cargo test $(TEST) $(CARGO_BUILD_ARGS) -- --nocapture

test-panic: override FEATURES += panic-on-error
test-panic:
	RUST_BACKTRACE=1 \
		cargo test \
			$(TEST) \
			$(CARGO_BUILD_ARGS) -- \
			--nocapture

test-st:
	cargo test $(TEST) $(CARGO_BUILD_ARGS) -- --nocapture --test-threads 1

clean:
	rm -rf target/
	cargo clean

