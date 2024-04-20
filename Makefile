.PHONY: all clean lint fmt release doc build run test test-panic test-st macros osx windows target/windows/stamp-cli.exe target/osx/stamp-cli

# non-versioned include
VARS ?= vars.mk
FMT ?= 1
-include $(VARS)

override CARGO_BUILD_ARGS += --features "$(FEATURES)" --color=always

all: build

run: build
	cargo run $(CARGO_BUILD_ARGS)

build: fmt
	cargo build $(CARGO_BUILD_ARGS)

fmt:
	if [ "$(FMT)" == "1" ]; then cargo fmt; fi

release: override CARGO_BUILD_ARGS += --release
release: build

doc:
	cargo doc $(CARGO_BUILD_ARGS)

test: fmt
	cargo test $(TEST) $(CARGO_BUILD_ARGS) -- --nocapture

test-release: override CARGO_BUILD_ARGS += --release
test-release: test

test-panic: override FEATURES += panic-on-error
test-panic: fmt
	RUST_BACKTRACE=1 \
		cargo test \
			$(TEST) \
			$(CARGO_BUILD_ARGS) -- \
			--nocapture

test-st: fmt
	cargo test $(TEST) $(CARGO_BUILD_ARGS) -- --nocapture --test-threads 1

lint:
	cargo clippy $(CARGO_BUILD_ARGS) -- \
		-A clippy::comparison_chain \
		-A clippy::module_inception \
		-A clippy::redundant_closure \
		-A clippy::redundant_pattern_matching \
		-A clippy::search_is_some

clean:
	rm -rf target/
	cargo clean

target/windows/stamp-cli.exe:
	@mkdir -p $(@D)
	ssh \
		User@localhost \
		-p 2223 \
		'cd \Users\User\dev\stamp\core && git reset --hard && git pull && cd ..\aux2 && git reset --hard && git pull && cd ..\cli && git reset --hard && git pull && sed -i "s|\.\./aux|../aux2|g" Cargo.toml && make release'
	scp -P 2223 'User@localhost:/Users/User/dev/stamp/cli/target/release/stamp-cli.exe' $@

target/osx/stamp-cli:
	@mkdir -p $(@D)
	ssh \
		andrew@localhost \
		-p 2222 \
		'cd ~/dev/stamp/core && git reset --hard && git pull && cd ../aux && git reset --hard && git pull && cd ../cli && git reset --hard && git pull && make release'
	scp -P 2222 'andrew@localhost:~/dev/stamp/cli/target/release/stamp-cli' $@

osx: target/osx/stamp-cli
windows: target/windows/stamp-cli.exe

