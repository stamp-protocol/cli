.PHONY: all clean release doc build run test test-panic test-st macros osx windows target/windows/stamp-cli.exe target/osx/stamp-cli

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

