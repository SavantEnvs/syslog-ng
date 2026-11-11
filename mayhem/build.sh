#!/usr/bin/env bash
#
# mayhem/build.sh — builds syslog-ng three ways, offline:
#   1. mayhem/build-fuzz : the whole project with ASan+UBSan+SanCov (what the harnesses link),
#   2. /mayhem/fuzz_<name> and /mayhem/fuzz_<name>-standalone : the harnesses,
#   3. mayhem/build-test : the unit-test suite and KAT probe with the project's normal flags
#      (test.sh only RUNS these).
# Submodules (ivykis, opentelemetry-proto, jwt-cpp) are never fetched: ivykis comes from apt, and the
# gRPC/C++ modules that need the other two are disabled.
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

SRC="${SRC:-/mayhem}"
cd "$SRC"

CMAKE_COMMON=(-G Ninja -DGIT_SUBMODULE=OFF -DIVYKIS_SOURCE=system -DENABLE_PYTHON=OFF -DENABLE_CPP=OFF
              -DENABLE_GRPC=OFF -DENABLE_JAVA=OFF -DCMAKE_C_COMPILER="$CC")

# 1) Sanitized project build (SanCov via -fsanitize=fuzzer-no-link so the library itself has coverage).
BF="$SRC/mayhem/build-fuzz"
# -fno-sanitize=null,object-size: upstream's NV_ENTRY_DIRECT_HDR (lib/logmsg/nvtable.h) is the offsetof idiom
# &((NVEntry *) NULL)->vdirect.data, which UBSan reports on every message (both checks must be off at -O2).
# Real NULL dereferences and out-of-bounds accesses still fault under ASan.
SF="$SANITIZER_FLAGS -fno-sanitize=null,object-size -fsanitize=fuzzer-no-link"
# Upstream's FindIVYKIS aborts when cmake is re-run on an existing cache, so always configure fresh.
rm -rf "$BF"
cmake -S . -B "$BF" "${CMAKE_COMMON[@]}" -DCMAKE_BUILD_TYPE= -DBUILD_TESTING=OFF \
      -DCMAKE_C_FLAGS="$SF $DEBUG_FLAGS" \
      -DCMAKE_EXE_LINKER_FLAGS="$SANITIZER_FLAGS" -DCMAKE_SHARED_LINKER_FLAGS="$SANITIZER_FLAGS" \
      -DCMAKE_MODULE_LINKER_FLAGS="$SANITIZER_FLAGS"
cmake --build "$BF" -j"$MAYHEM_JOBS"

# 2) Harnesses, each twice: libFuzzer engine and the standalone run-once driver.
PKGS="glib-2.0 gmodule-2.0 ivykis"
INC=(-I"$SRC/lib" -I"$BF/lib" -I"$BF" -I"$SRC" -I"$SRC/modules/syslogformat" -I"$SRC/modules/correlation"
     -I"$SRC/lib/eventlog/src" $(pkg-config --cflags $PKGS))
CORE=("$BF"/lib/libsyslog-ng-*.so.0 "$BF"/lib/eventlog/libevtlog-*.so.0)
FMT="$BF/modules/syslogformat/libsyslogformat.so"
COR="$BF/modules/correlation/libcorrelation.so"
RPATH=(-Wl,-rpath,"$BF/lib" -Wl,-rpath,"$BF/lib/eventlog" -Wl,-rpath,"$BF/modules/syslogformat" -Wl,-rpath,"$BF/modules/correlation")
LIBS=($(pkg-config --libs $PKGS) -lm)

$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.cc" -o "$BF/lsan_off.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$BF/standalone_main.o"

build_harness() {
  local name="$1"; shift
  local src="$SRC/mayhem/$name.c"
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "${INC[@]}" "$src" "$BF/lsan_off.o" \
      "$@" "${CORE[@]}" "${RPATH[@]}" "${LIBS[@]}" -o "/mayhem/$name"
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS "${INC[@]}" "$src" "$BF/standalone_main.o" "$BF/lsan_off.o" \
      "$@" "${CORE[@]}" "${RPATH[@]}" "${LIBS[@]}" -o "/mayhem/$name-standalone"
}
build_harness fuzz_syslog_format "$FMT"
build_harness fuzz_logmsg_deserialize
build_harness fuzz_logproto
build_harness fuzz_radix "$COR"

# 3) Test suite and KAT probe with the project's normal flags.
BT="$SRC/mayhem/build-test"
rm -rf "$BT"
cmake -S . -B "$BT" "${CMAKE_COMMON[@]}" -DCMAKE_BUILD_TYPE=RelWithDebInfo -DBUILD_TESTING=ON \
      -DCMAKE_C_FLAGS="$COVERAGE_FLAGS" -DCMAKE_EXE_LINKER_FLAGS="$COVERAGE_FLAGS" \
      -DCMAKE_SHARED_LINKER_FLAGS="$COVERAGE_FLAGS" -DCMAKE_MODULE_LINKER_FLAGS="$COVERAGE_FLAGS"
cmake --build "$BT" -j"$MAYHEM_JOBS" --target syslogformat correlation test_syslog_format test_msgparse test_logmsg_serialize \
      test_nvtable test_log_message test_logproto test_radix test_parsers
$CC -O2 $COVERAGE_FLAGS "${INC[@]/$BF/$BT}" "$SRC/mayhem/kat_probe.c" \
    "$BT"/lib/libsyslog-ng-*.so.0 "$BT"/lib/eventlog/libevtlog-*.so.0 "$BT/modules/syslogformat/libsyslogformat.so" "$BT/modules/correlation/libcorrelation.so" \
    -Wl,-rpath,"$BT/lib" -Wl,-rpath,"$BT/lib/eventlog" -Wl,-rpath,"$BT/modules/syslogformat" -Wl,-rpath,"$BT/modules/correlation" \
    "${LIBS[@]}" -o "$BT/kat_probe"
