#!/usr/bin/env bash
# Compiles the datapath C program into target/ebpf/datapath.o.
#
# The datapath is a separate artifact: it is C, it is compiled by clang -target
# bpf, and it is loaded (not linked) by `daer-ebpf`. Its source and the vmlinux
# headers are inputs to this script, not vendored files, so this script takes
# paths:
#
#   DAER_DATAPATH_SRC   directory holding the datapath C source and headers
#                       (default: ebpf/kern, i.e. daer's own copy once vendored)
#   DAER_BPF_HEADERS    directory holding vmlinux.h (default: ebpf/headers)
#   MAX_MATCH_SET_LEN   must match the value the userspace side was built with
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
datapath_src="${DAER_DATAPATH_SRC:-$root/ebpf/kern}"
headers="${DAER_BPF_HEADERS:-$root/ebpf/headers}"
max_match_set_len="${MAX_MATCH_SET_LEN:-1024}"
clang="${CLANG:-clang}"
out_dir="$root/target/ebpf"

case "$(uname -m)" in
    x86_64) bpf_arch=x86 ;;
    aarch64 | arm64) bpf_arch=arm64 ;;
    riscv64) bpf_arch=riscv ;;
    ppc64le | powerpc64le) bpf_arch=powerpc ;;
    loongarch64) bpf_arch=loongarch ;;
    *)
        echo "error: unsupported architecture $(uname -m); set DAER_BPF_ARCH" >&2
        echo "       (one of x86, arm64, riscv, powerpc, loongarch)" >&2
        exit 1
        ;;
esac
bpf_arch="${DAER_BPF_ARCH:-$bpf_arch}"

if [ ! -d "$datapath_src" ]; then
    echo "error: datapath source not found at $datapath_src" >&2
    echo "       set DAER_DATAPATH_SRC to a directory containing the C source and" >&2
    echo "       its include/ tree; see docs/roadmap.md (datapath ownership)." >&2
    exit 1
fi
if [ ! -f "$headers/vmlinux.h" ]; then
    echo "error: $headers/vmlinux.h is missing" >&2
    echo "       point DAER_BPF_HEADERS at a vmlinux.h tree, or fetch the BPF headers" >&2
    echo "       repository into $headers yourself." >&2
    exit 1
fi

build="$out_dir/build"
rm -rf "$build"
mkdir -p "$build"
cp "$datapath_src"/*.c "$datapath_src"/*.h "$build/"
ln -sfn "$headers" "$build/headers"
ln -sfn "$datapath_src/include" "$build/include"

"$clang" -O2 -g -Wall -Werror -Wno-missing-declarations -target bpf \
    -D"__TARGET_ARCH_${bpf_arch}" \
    -D"MAX_MATCH_SET_LEN=${max_match_set_len}" \
    -I"$build" \
    -c "$build/tproxy.c" \
    -o "$out_dir/datapath.o"

echo "built $out_dir/datapath.o"
