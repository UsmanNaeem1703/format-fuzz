# FormatFuzzer × AFL++ — PNG format-aware fuzzing

This directory contains a complete, working integration of
[FormatFuzzer](https://github.com/uds-se/FormatFuzzer) with the latest
[AFL++](https://github.com/AFLplusplus/AFLplusplus) (built from source,
`afl-fuzz++5.04a`) for coverage-guided, PNG-format-aware fuzzing of a real
libpng parser.

## Layout

| Path | Contents |
|---|---|
| `AFLplusplus/` | AFL++ source, built with `make distrib` (latest stable) |
| `FormatFuzzer/` | FormatFuzzer source; `png.cpp` generated via `./ffcompile templates/png.bt png.cpp` |
| `ffmut/ffmut.cpp` | **The custom mutator** — all 16 AFL++ custom-mutator APIs implemented; format-agnostic, links against any generated `<FORMAT>.cpp` |
| `ffmut/ffmut-png.so` | Built mutator (FormatFuzzer PNG generator/parser + glue, one self-contained .so) |
| `ffmut/Makefile` | `make` (default png) / `make FORMAT=gif` / `make all-formats`; auto-runs `ffcompile` if `<FORMAT>.cpp` missing. Plain g++ only! |
| `target/` | zlib + libpng + `png_harness.c`, all built with `afl-clang-fast` (static) |
| `target/png_harness` | Instrumented target: full PNG decode of `@@` |
| `seeds_png/` | Seed corpus: AFL++ `testcases/images/png/*.png` (all decode cleanly) |
| `seeds_dec/` | Same seeds converted to FormatFuzzer decision files (`png-fuzzer parse --decisions …`) |
| `out_ffmut/`, `out_ffgen/`, `out_plain/` | 90-second example campaigns |

## The custom mutator (`ffmut-png.so`)

Exports the complete AFL++ custom mutator API (verified with
`nm -D ffmut-png.so`):

`afl_custom_init`, `afl_custom_introspection`, `afl_custom_fuzz_count`,
`afl_custom_splice_optout`, `afl_custom_fuzz`, `afl_custom_describe`,
`afl_custom_post_process`, `afl_custom_init_trim`, `afl_custom_trim`,
`afl_custom_post_trim`, `afl_custom_havoc_mutation`,
`afl_custom_havoc_mutation_probability`, `afl_custom_queue_get`,
`afl_custom_fuzz_send`, `afl_custom_queue_new_entry`, `afl_custom_deinit`.

Implementation notes:

- **FFMut (default)** — `afl_custom_fuzz` maps the parent PNG into
  FormatFuzzer *decision space* (`ff_parse`), mutates decision bytes,
  maps back to a binary PNG (`ff_generate`). Mixes in fully-random
  generation (`generate_random_file`), decision-space splicing when AFL++
  supplies `add_buf`, and plain byte havoc as fallback.
- **FFGen (`FFGEN=1`)** — the AFL++ queue holds *decision files*; AFL++
  mutates them natively, and `afl_custom_post_process` translates each
  mutated decision file into a binary PNG via `ff_generate()` just before
  execution.
- **Trimming** — decision-space trimming: iteratively truncates the
  decision file (½, ¼, ⅛, …) and regenerates the binary. Never returns
  NULL (AFL++ treats that as fatal); falls back to the parent binary.
- **`afl_custom_fuzz_send`** — because AFL++ *skips its own testcase
  write* when this symbol is exported, the hook performs the write itself
  (mirrors `afl_fsrv_write_to_testcase` for shmem and file/fd transports).
  With `AFL_CUSTOM_MUTATOR_LATE_SEND=1` AFL++ instead delivers the buffer
  through `fsrv->custom_input` after target restart.
- **Gotcha**: build the mutator with a **plain compiler**. With
  `afl-clang-fast` the .so gets undefined `__afl_area_ptr` and afl-fuzz
  aborts at load time.

Environment knobs: `FFGEN=1`, `FFMUT_P_RANDOM` (default 5),
`FFMUT_P_DIRECT` (10), `FFMUT_P_SPLICE` (50), `FFMUT_DECISION_MUTS` (4).

## Getting the sources

This repo contains the integration (mutator, harness, seeds, docs). The
three upstream checkouts it builds against are not vendored — clone them
next to (or inside) this repo first:

```sh
git clone https://github.com/AFLplusplus/AFLplusplus
git clone https://github.com/uds-se/FormatFuzzer
cd target
git clone https://github.com/madler/zlib
git clone --branch libpng16 https://github.com/glennrp/libpng
cd ..
```

## Build

```sh
# 1. AFL++ (llvm-18/clang-18 already installed on this machine)
cd AFLplusplus && git submodule update --init && make distrib

# 2. FormatFuzzer python deps + png.cpp
cd ../FormatFuzzer
python3 -m venv ~/fuzz && source ~/fuzz/bin/activate
pip3 install py010parser six intervaltree
./ffcompile templates/png.bt png.cpp

# 3. custom mutator (png is the default FORMAT)
cd ../ffmut && make                    # -> ffmut-png.so

# any other template works the same way; the Makefile auto-generates
# <FORMAT>.cpp from templates/<FORMAT>.bt via ffcompile when missing:
make FORMAT=gif                        # -> ffmut-gif.so
make FORMAT=jpg                        # -> ffmut-jpg.so
make FORMAT=bmp                        # -> ffmut-bmp.so
# or build one .so for every templates/*.bt (skips *-orig.bt):
make all-formats                       # -> ffmut-png.so, ffmut-gif.so, ...

# sanity: 16 exported APIs, no AFL instrumentation symbols
nm -D ffmut-png.so | grep -c " T afl_custom"          # -> 16
nm -D --undefined-only ffmut-png.so | grep -c "__afl_" # -> 0  (must be 0!)

# 4. instrumented target (zlib, libpng, harness)
#    NOTE: never export AFL_CC/AFL_CXX pointing at afl-clang-fast — afl-cc
#    then wraps itself and dies with "Too many command line parameters".
#    Use plain CC=... per command as below.
export AFLL=$PWD/AFLplusplus          # adjusts AFL++ dir
export T=$PWD/target                  # target workdir

# 4a. zlib (static, instrumented)
cd $T/zlib
CC=$AFLL/afl-clang-fast ./configure --static --prefix=$T/build
make -j"$(nproc)"
make install                          # installs $T/build/lib/libz.a + include/zlib.h

# 4b. libpng (static, instrumented) — first make generates pnglibconf.h
#     with the SYSTEM zlib version and then fails on the version check;
#     patch the macro to match our zlib and build again.
cd $T/libpng
CC=$AFLL/afl-clang-fast CFLAGS="-O2 -I$T/build/include" \
   LDFLAGS="-L$T/build/lib" ./configure --prefix=$T/build --disable-shared
make -j"$(nproc)" || true
ZV=$(grep -o 'ZLIB_VERNUM 0x[0-9a-f]*' $T/build/include/zlib.h | head -1 | awk '{print $2}')
PV=$(grep -o 'PNG_ZLIB_VERNUM 0x[0-9a-f]*' pnglibconf.h | head -1 | awk '{print $2}')
[ "$ZV" != "$PV" ] && sed -i "s/#define PNG_ZLIB_VERNUM $PV/#define PNG_ZLIB_VERNUM $ZV/" pnglibconf.h
make -j"$(nproc)"
make install                          # installs $T/build/lib/libpng.a + include/png.h

# 4c. harness
cd $T
$AFLL/afl-clang-fast -O2 -I build/include png_harness.c -o png_harness \
   build/lib/libpng.a build/lib/libz.a -lm
# verify: ./png_harness ../seeds_png/not_kitty.png -> exit 0
#         afl-showmap must report ~500 tuples
```

## Run

```sh
# AFL+FFMut
AFL_CUSTOM_MUTATOR_LIBRARY=$PWD/ffmut/ffmut-png.so \
  ./AFLplusplus/afl-fuzz -i seeds_png -o out_ffmut -m none -- ./target/png_harness @@

# AFL+FFGen
FFGEN=1 AFL_CUSTOM_MUTATOR_LIBRARY=$PWD/ffmut/ffmut-png.so \
  ./AFLplusplus/afl-fuzz -i seeds_dec -o out_ffgen -m none -- ./target/png_harness @@
```

For any other format (e.g. gif): swap the mutator, the seed corpus, and —
importantly — the *target*, which must be a program that parses that format
(the mutator only generates/mutates inputs; coverage still comes from the
instrumented parser you fuzz):

```sh
AFL_CUSTOM_MUTATOR_LIBRARY=$PWD/ffmut/ffmut-gif.so \
  ./AFLplusplus/afl-fuzz -i seeds_gif -o out_gif -m none -- ./target/gif_harness @@
```

## Measured results (90 s each, this machine)

| Campaign | execs | bitmap coverage | corpus | PNG-structured |
|---|---|---|---|---|
| AFL+FFMut | 535,169 | **15.37%** | 576 | 560/576 (97%) |
| AFL+FFGen | 500,783 | 12.43% | 308 | decision files → valid PNGs |
| plain AFL++ | 552,780 | 12.11% | 484 | 472/484 |

## Sanity checks used

```sh
# mutator not instrumented (must print nothing)
nm -D --undefined-only ffmut/ffmut-png.so | grep -E "__afl_|__sanitizer_"

# seeds decode cleanly
for f in seeds_png/*.png; do ./target/png_harness $f; echo "$f -> $?"; done

# FFGen queue entry -> PNG
./FormatFuzzer/png-fuzzer fuzz --decisions out_ffgen/default/queue/<id> /tmp/check.png
```
