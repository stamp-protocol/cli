.PHONY: all clean release doc build run test test-panic test-st macros

# non-versioned include
VARS ?= vars.mk
-include $(VARS)

CARGO ?= $(shell which cargo)
override CARGO_BUILD_ARGS += --features "$(FEATURES)" --color=always

all: build

run: build
	$(CARGO) run $(CARGO_BUILD_ARGS)

build:
	$(CARGO) build $(CARGO_BUILD_ARGS)

release: override CARGO_BUILD_ARGS += --release
release: build

doc:
	cargo doc

test-release: override CARGO_BUILD_ARGS += --release
test-release:
	$(CARGO) test $(TEST) $(CARGO_BUILD_ARGS) -- --nocapture

test:
	$(CARGO) test $(TEST) $(CARGO_BUILD_ARGS) -- --nocapture

test-panic: override FEATURES += panic-on-error
test-panic:
	RUST_BACKTRACE=1 \
		$(CARGO) test \
			$(TEST) \
			$(CARGO_BUILD_ARGS) -- \
			--nocapture

test-st:
	$(CARGO) test $(TEST) $(CARGO_BUILD_ARGS) -- --nocapture --test-threads 1

clean:
	rm -rf target/
	cargo clean

