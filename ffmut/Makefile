# Makefile for FormatFuzzer custom mutators for AFL++
#
# Builds ffmut-<FORMAT>.so: a self-contained AFL++ custom mutator for the
# format described by templates/<FORMAT>.bt (FormatFuzzer).
#
#   make                -> ffmut-png.so
#   make FORMAT=gif     -> ffmut-gif.so
#   make FORMAT=jpg     -> ffmut-jpg.so
#   make all-formats    -> one .so per templates/*.bt present
#
# IMPORTANT: use the plain system g++ (no afl-clang-fast/afl-gcc): an
# instrumented mutator .so aborts afl-fuzz at load time with
# "undefined symbol: __afl_area_ptr".

FORMAT  ?= png

AFL_INCLUDE := ../AFLplusplus/include
FF_DIR      := ../FormatFuzzer

CXX      ?= g++
CXXFLAGS := -I $(AFL_INCLUDE) -I $(FF_DIR) -std=c++17 -g -O2 -Wall -fPIC

all: ffmut-$(FORMAT).so

# Generated C++ for the format (created by ffcompile from templates/<fmt>.bt).
# Requires the FormatFuzzer python venv (py010parser, six, intervaltree).
$(FF_DIR)/$(FORMAT).cpp: $(FF_DIR)/templates/$(FORMAT).bt
	cd $(FF_DIR) && . ~/fuzz/bin/activate && ./ffcompile templates/$(FORMAT).bt $(FORMAT).cpp

$(FORMAT).o: $(FF_DIR)/$(FORMAT).cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

fuzzer.o: $(FF_DIR)/fuzzer.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

ffmut.o: ffmut.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

ffmut-$(FORMAT).so: fuzzer.o $(FORMAT).o ffmut.o
	$(CXX) $(CXXFLAGS) -shared -o $@ fuzzer.o $(FORMAT).o ffmut.o -lz

# build one .so for every templates/<name>.bt (skips *-orig.bt variants)
all-formats:
	@for bt in $(FF_DIR)/templates/*.bt; do \
	  fmt=$$(basename $$bt .bt); \
	  case $$fmt in *-orig) continue;; esac; \
	  echo "=== building ffmut-$$fmt.so ==="; \
	  $(MAKE) --no-print-directory FORMAT=$$fmt || exit 1; \
	done

clean:
	rm -f *.o *.so

.PHONY: all all-formats clean
