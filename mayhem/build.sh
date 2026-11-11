#!/usr/bin/env bash
#
# mayhem/build.sh — build zapret2's nfqws2 (the sanitized fuzz harnesses + a plain test build).
# Runs inside the commit image (mayhem/Dockerfile) as `mayhem` in /mayhem; offline and re-runnable.
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' (empty) — it must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"
B="$SRC/mayhem/build"
mkdir -p "$B/fuzz" "$B/test"

LUA_CFLAGS="$(pkg-config --cflags lua5.4)"
LUA_LIBS="$(pkg-config --libs lua5.4)"
SYS_LIBS="-lz -lnetfilter_queue -lnfnetlink -lmnl -lm"
# nfqws.c defines main(); renaming it lets the harnesses link the whole program.
COMMON="-std=gnu99 $LUA_CFLAGS -fPIC"
SRCS=$(ls nfq2/*.c nfq2/crypto/*.c)

compile_one() { # <outdir> <flags...> <src>
  local out="$1"; shift
  local src="${!#}"
  local extra=""
  [ "$src" = "nfq2/nfqws.c" ] && extra="$MAIN_RENAME"
  "$CC" "${@:1:$#-1}" $extra -c "$src" -o "$out/$(echo "$src" | tr '/' '_').o"
}
export -f compile_one

# 1) The project itself, instrumented with the sanitizers + DWARF 3 (fuzzed code is nfq2/*).
FUZZ_FLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS -O1 $COMMON -fsanitize=fuzzer-no-link"
rm -f "$B"/fuzz/*.o
export MAIN_RENAME="-Dmain=nfqws_main"
printf '%s\n' $SRCS | xargs -P "$MAYHEM_JOBS" -I{} bash -c 'compile_one "$@"' _ "$B/fuzz" $FUZZ_FLAGS {}
FUZZ_OBJS=$(ls "$B"/fuzz/nfq2_*.o)

# LeakSanitizer off at build time (leaks are not the bug class fuzzed here).
"$CXX" $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.cc" -o "$B/lsan_off.o"
"$CC" $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$B/standalone_main.o"

# 2) Harnesses: libFuzzer binary + standalone run-once reproducer each.
for h in fuzz_protocol fuzz_quic fuzz_tlsmod fuzz_hostlist fuzz_lua fuzz_packet; do
  [ -f "$SRC/mayhem/$h.c" ] || continue
  "$CC" $SANITIZER_FLAGS $DEBUG_FLAGS -O1 $COMMON -iquote "$SRC/nfq2" -c "$SRC/mayhem/$h.c" -o "$B/$h.o"
  "$CC" $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "$B/$h.o" $FUZZ_OBJS "$B/lsan_off.o" \
      $LUA_LIBS $SYS_LIBS -o "/mayhem/$h"
  "$CC" $SANITIZER_FLAGS $DEBUG_FLAGS "$B/standalone_main.o" "$B/$h.o" $FUZZ_OBJS "$B/lsan_off.o" \
      $LUA_LIBS $SYS_LIBS -o "/mayhem/$h-standalone"
done

# 3) The test build: plain flags, no sanitizers. test.sh runs upstream's lua/zapret-tests.lua through
#    test_driver (nfqws2 itself can't run Lua as non-root: dropcaps() needs CAP_SETPCAP).
rm -f "$B"/test/*.o
export MAIN_RENAME="-Dmain=nfqws_main"
TEST_FLAGS="-std=gnu99 -O2 $COMMON $COVERAGE_FLAGS"
printf '%s\n' $SRCS | xargs -P "$MAYHEM_JOBS" -I{} bash -c 'compile_one "$@"' _ "$B/test" $TEST_FLAGS {}
"$CC" $TEST_FLAGS -iquote "$SRC/nfq2" -c "$SRC/mayhem/test_driver.c" -o "$B/test_driver.o"
"$CC" $COVERAGE_FLAGS "$B/test_driver.o" "$B"/test/nfq2_*.o $LUA_LIBS $SYS_LIBS -o "$B/test_driver"
