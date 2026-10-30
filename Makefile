CARGO ?= cargo

.PHONY: all build check fmt fmt-check clippy test ci clean ebpf pins schema

all: build

build:
	$(CARGO) build --workspace --release

check:
	$(CARGO) check --workspace --all-targets

fmt:
	$(CARGO) fmt --all

fmt-check:
	$(CARGO) fmt --all -- --check

clippy:
	$(CARGO) clippy --workspace --all-targets -- -D warnings

test:
	$(CARGO) test --workspace

# Fails when a configuration key is accepted and never consumed (ADR-0006). Needs no
# privilege and no network, so it can run before the slower jobs.
keys:
	./scripts/check-config-keys.py

# Verifies that the path dependency on ../netune still matches pins/netune.toml.
pins:
	./scripts/check-pins.sh

# Regenerates the published JSON Schema. CI fails when the checked-in file drifts.
schema:
	$(CARGO) run -q -p daer-cli -- config schema > daer.schema.json

# The checked-in schema is the one editors and CI consume; regenerating it is a
# reviewable diff, not a build side effect.
schema-check:
	$(CARGO) run -q -p daer-cli -- config schema | diff -u daer.schema.json -

ci: fmt-check clippy keys pins schema-check test

# Compiles the datapath C program into target/ebpf/datapath.o. Needs clang, the
# datapath source (DAER_DATAPATH_SRC) and a vmlinux.h tree (DAER_BPF_HEADERS).
ebpf:
	./scripts/build-ebpf.sh

clean:
	$(CARGO) clean
