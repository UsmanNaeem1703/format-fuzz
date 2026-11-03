/*
   ffmut.cpp - FormatFuzzer custom mutator for AFL++ (PNG)

   Integrates FormatFuzzer (https://github.com/uds-se/FormatFuzzer)
   with AFL++ (https://github.com/AFLplusplus/AFLplusplus) for
   format-aware fuzzing of PNG parsers.

   Implements the complete AFL++ custom mutator API:
     afl_custom_init, afl_custom_introspection, afl_custom_fuzz_count,
     afl_custom_splice_optout, afl_custom_fuzz, afl_custom_describe,
     afl_custom_post_process, afl_custom_init_trim, afl_custom_trim,
     afl_custom_post_trim, afl_custom_havoc_mutation,
     afl_custom_havoc_mutation_probability, afl_custom_queue_get,
     afl_custom_fuzz_send, afl_custom_queue_new_entry, afl_custom_deinit

   Two strategies (see README.md):

   * FFMUT (default) - AFL+FFMut:
     afl_custom_fuzz() treats the parent test case as a binary PNG,
     maps it into FormatFuzzer's decision space with ff_parse(),
     applies random decision-space mutations, and maps back to a binary
     PNG with ff_generate(). The result is a structurally valid (or
     near-valid) mutated PNG. Fully random generation and classic
     byte-level havoc are mixed in with configurable probabilities.

   * FFGen (env FFGEN=1) - AFL+FFGen:
     The AFL++ queue holds FormatFuzzer *decision files*. AFL++ mutates
     those decision files with its own mutators (afl_custom_fuzz only
     does light decision-space cleanup). afl_custom_post_process()
     translates the mutated decision file into a binary PNG via
     ff_generate() right before the target executes.

   Build:  make            (uses ../FormatFuzzer sources, ../AFLplusplus/include)
*/

#include "afl-fuzz.h"
#include "alloc-inl.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* FormatFuzzer core API (defined in bt.h / fuzzer.cpp) */
extern "C" size_t ff_generate(unsigned char *data, size_t size,
                              unsigned char **new_data);
extern "C" int    ff_parse(unsigned char *data, size_t size,
                           unsigned char **new_data, size_t *new_size);
extern "C" void   generate_random_file(unsigned char **file,
                                       unsigned *file_size);

#define MAX_RAND_SIZE_FFMUT 131072
#define MAX_FILE_SIZE_FFMUT 65536

typedef struct ffmutator {

  afl_state_t *afl;
  unsigned int seed;

  /* ---- buffers under our own memory management ---- */
  u8 *out_buf;           /* returned by afl_custom_fuzz / afl_custom_trim */
  size_t out_buf_size;
  u8 *post_buf;          /* returned by afl_custom_post_process */
  size_t post_buf_size;
  u8 *decisions;         /* scratch: decision file of current parent */
  size_t decisions_size;

  /* ---- trimming state ---- */
  u8 *trim_decisions;    /* decision file of the trim candidate */
  size_t trim_decisions_size;
  u8 *trim_fallback;     /* last known good binary (full regen of buf) */
  size_t trim_fallback_size;
  size_t trim_steps;     /* total steps returned by init_trim */
  size_t trim_step;      /* current step */
  size_t trim_candidate; /* current decision cut length */

  /* ---- configuration (env-tunable) ---- */
  u32 p_random;          /* % chance: fully random generation */
  u32 p_direct;          /* % chance: plain byte havoc (fallback) */
  u32 p_splice;          /* % chance: decision-space splice w/ add_buf */
  u32 decision_muts;     /* byte mutations applied to decision files */
  int ffgen_mode;        /* 1 = FFGen strategy, 0 = FFMut strategy */

  /* ---- stats / metadata ---- */
  char describe_buf[256];
  char introspection_buf[512];
  u64 n_random, n_decision, n_splice, n_direct, n_parse_fail, n_gen_fail,
      n_trim, n_post, n_queue, n_send;

} ffmutator_t;

/* ------------------------------------------------------------------ */
/* helpers                                                            */
/* ------------------------------------------------------------------ */

static u32 rnd_below(ffmutator_t *data, u32 limit) {

  (void)data;
  return (u32)(random() % limit);

}

static void set_desc(ffmutator_t *data, const char *fmt, const char *arg) {

  snprintf(data->describe_buf, sizeof(data->describe_buf), fmt, arg);

}

/* grow out_buf to at least size bytes */
static u8 *ensure_out(ffmutator_t *data, size_t size) {

  if (data->out_buf_size < size) {

    u8 *nb = (u8 *)realloc(data->out_buf, size);
    if (!nb) return NULL;
    data->out_buf = nb;
    data->out_buf_size = size;

  }

  return data->out_buf;

}

/* grow post_buf to at least size bytes */
static u8 *ensure_post(ffmutator_t *data, size_t size) {

  if (data->post_buf_size < size) {

    u8 *nb = (u8 *)realloc(data->post_buf, size);
    if (!nb) return NULL;
    data->post_buf = nb;
    data->post_buf_size = size;

  }

  return data->post_buf;

}

/* grow decisions scratch to at least size bytes */
static u8 *ensure_decisions(ffmutator_t *data, size_t size) {

  if (data->decisions_size < size) {

    u8 *nb = (u8 *)realloc(data->decisions, size);
    if (!nb) return NULL;
    data->decisions = nb;
    data->decisions_size = size;

  }

  return data->decisions;

}

/* parse binary -> copy of decision file; returns decision size or 0 */
static size_t parse_to_decisions(ffmutator_t *data, u8 *buf, size_t buf_size) {

  u8 *dec = NULL;
  size_t dec_size = 0;

  if (buf_size > MAX_FILE_SIZE_FFMUT) buf_size = MAX_FILE_SIZE_FFMUT;
  if (buf_size == 0) return 0;

  if (!ff_parse(buf, buf_size, &dec, &dec_size)) return 0;
  if (!dec || dec_size == 0) return 0;

  u8 *dst = ensure_decisions(data, dec_size);
  if (!dst) return 0;
  memcpy(dst, dec, dec_size);
  return dec_size;

}

/* generate binary from decision file (copy); returns size or 0.
   ff_generate() returns a pointer to an internal buffer that we copy
   into out_buf so we keep full ownership of the returned memory. */
static size_t generate_from_decisions(ffmutator_t *data, u8 *dec,
                                      size_t dec_size, size_t max_size) {

  u8 *gen = NULL;
  size_t gen_size = ff_generate(dec, dec_size, &gen);

  if (!gen || gen_size == 0) return 0;
  if (gen_size > max_size) return 0;

  u8 *dst = ensure_out(data, gen_size);
  if (!dst) return 0;
  memcpy(dst, gen, gen_size);
  return gen_size;

}

/* classic byte-level havoc on a copy of buf */
static size_t direct_havoc(ffmutator_t *data, u8 *buf, size_t buf_size,
                           size_t max_size) {

  if (buf_size == 0) return 0;
  u8 *dst = ensure_out(data, buf_size);
  if (!dst) return 0;
  memcpy(dst, buf, buf_size);

  u32 mutations = 1 + rnd_below(data, 8);
  for (u32 i = 0; i < mutations; ++i) {

    size_t pos = rnd_below(data, buf_size);
    switch (rnd_below(data, 4)) {

      case 0:
        dst[pos] ^= (u8)(1 << rnd_below(data, 8));
        break;
      case 1:
        dst[pos] = (u8)random();
        break;
      case 2:
        dst[pos] += (u8)(1 + rnd_below(data, 35));
        break;
      default:
        dst[pos] -= (u8)(1 + rnd_below(data, 35));
        break;

    }

  }

  if (buf_size > max_size) buf_size = max_size;
  return buf_size;

}

/* ------------------------------------------------------------------ */
/* 1. afl_custom_init                                                  */
/* ------------------------------------------------------------------ */

extern "C" void *afl_custom_init(afl_state_t *afl, unsigned int seed) {

  srandom(seed);
  srand(seed);

  ffmutator_t *data = (ffmutator_t *)calloc(1, sizeof(ffmutator_t));
  if (!data) {

    perror("ffmut: afl_custom_init calloc");
    return NULL;

  }

  data->afl = afl;
  data->seed = seed;

  data->out_buf_size = MAX_FILE_SIZE_FFMUT;
  data->out_buf = (u8 *)malloc(data->out_buf_size);
  data->post_buf_size = MAX_FILE_SIZE_FFMUT;
  data->post_buf = (u8 *)malloc(data->post_buf_size);
  data->decisions_size = MAX_RAND_SIZE_FFMUT;
  data->decisions = (u8 *)malloc(data->decisions_size);

  if (!data->out_buf || !data->post_buf || !data->decisions) {

    perror("ffmut: afl_custom_init malloc");
    free(data->out_buf);
    free(data->post_buf);
    free(data->decisions);
    free(data);
    return NULL;

  }

  /* configuration via environment */
  char *env;
  data->ffgen_mode =
      (env = getenv("FFGEN")) && env[0] == '1';
  data->p_random =
      (env = getenv("FFMUT_P_RANDOM")) ? (u32)atoi(env) : 5;
  data->p_direct =
      (env = getenv("FFMUT_P_DIRECT")) ? (u32)atoi(env) : 10;
  data->p_splice =
      (env = getenv("FFMUT_P_SPLICE")) ? (u32)atoi(env) : 50;
  data->decision_muts =
      (env = getenv("FFMUT_DECISION_MUTS")) ? (u32)atoi(env) : 4;

  if (data->p_random + data->p_direct > 100) data->p_direct = 0;

  set_desc(data, "%s", "init");
  snprintf(data->introspection_buf, sizeof(data->introspection_buf),
           "ffmut init: mode=%s", data->ffgen_mode ? "ffgen" : "ffmut");

  if (afl && afl->debug) {

    fprintf(stderr,
            "ffmut: initialized (mode=%s, p_random=%u, p_direct=%u, "
            "p_splice=%u, decision_muts=%u)\n",
            data->ffgen_mode ? "ffgen" : "ffmut", data->p_random,
            data->p_direct, data->p_splice, data->decision_muts);

  }

  return data;

}

/* ------------------------------------------------------------------ */
/* 2. afl_custom_introspection                                         */
/* ------------------------------------------------------------------ */

extern "C" const char *afl_custom_introspection(void *ptr) {

  ffmutator_t *data = (ffmutator_t *)ptr;
  snprintf(data->introspection_buf, sizeof(data->introspection_buf),
           "ffmut: random=%llu decision=%llu splice=%llu direct=%llu "
           "parse_fail=%llu gen_fail=%llu trim=%llu post=%llu queue=%llu",
           (unsigned long long)data->n_random,
           (unsigned long long)data->n_decision,
           (unsigned long long)data->n_splice,
           (unsigned long long)data->n_direct,
           (unsigned long long)data->n_parse_fail,
           (unsigned long long)data->n_gen_fail,
           (unsigned long long)data->n_trim,
           (unsigned long long)data->n_post,
           (unsigned long long)data->n_queue);
  return data->introspection_buf;

}

/* ------------------------------------------------------------------ */
/* 3. afl_custom_fuzz_count                                            */
/* ------------------------------------------------------------------ */

extern "C" unsigned int afl_custom_fuzz_count(void *ptr, const u8 *buf,
                                              size_t buf_size) {

  (void)ptr;
  (void)buf;
  /* fuzz every queue entry; skip only degenerate empty seeds */
  return buf_size ? 1 : 0;

}

/* ------------------------------------------------------------------ */
/* 4. afl_custom_splice_optout                                         */
/* ------------------------------------------------------------------ */

extern "C" void afl_custom_splice_optout(void *ptr) {

  /* Intentionally a no-op. This mutator makes use of add_buf:
     when AFL++ hands us a splicing partner we splice the two parents
     in FormatFuzzer decision space (see afl_custom_fuzz). Exporting
     this symbol without opting out keeps the add_buf flowing. */
  ffmutator_t *data = (ffmutator_t *)ptr;
  (void)data;

}

/* ------------------------------------------------------------------ */
/* 5. afl_custom_fuzz                                                  */
/* ------------------------------------------------------------------ */

extern "C" size_t afl_custom_fuzz(void *ptr, u8 *buf, size_t buf_size,
                                  u8 **out_buf, u8 *add_buf,
                                  size_t add_buf_size, size_t max_size) {

  ffmutator_t *data = (ffmutator_t *)ptr;
  u32 choice = rnd_below(data, 100);

  /* ---------------- FFGen strategy ---------------- */
  if (data->ffgen_mode) {

    /* The queue entry is a FormatFuzzer decision file. Keep it in
       decision space: AFL++'s own havoc/splicing did the mutation; we
       only lightly re-randomize a few decision bytes to break plateaus.
       The binary PNG is produced later in afl_custom_post_process(). */
    size_t size = buf_size < max_size ? buf_size : max_size;
    u8 *dst = ensure_out(data, size ? size : 1);
    if (!dst) return 0;
    memcpy(dst, buf, size);

    if (size > 4 && (random() & 1)) {

      for (u32 i = 0; i < data->decision_muts; ++i) {

        size_t pos = rnd_below(data, size);
        dst[pos] ^= (u8)(1 << rnd_below(data, 8));

      }

    }

    data->n_decision++;
    set_desc(data, "ffgen-decision-mut[%zu]", "decision");
    *out_buf = dst;
    return size;

  }

  /* ---------------- FFMut strategy ---------------- */

  /* (a) fully random generation with probability p_random */
  if (choice < data->p_random) {

    unsigned char *file = NULL;
    unsigned file_size = 0;
    generate_random_file(&file, &file_size);

    if (file && file_size > 0 && file_size <= max_size) {

      u8 *dst = ensure_out(data, file_size);
      if (!dst) return 0;
      memcpy(dst, file, file_size);
      data->n_random++;
      set_desc(data, "ffmut-random-gen[%u]", "png");
      *out_buf = dst;
      return file_size;

    }

    /* fall through to decision mutation on failure */

  }

  /* (b) decision-space splice if AFL++ gave us a partner */
  if (add_buf && add_buf_size &&
      (choice < data->p_random + data->p_splice)) {

    size_t d1 = parse_to_decisions(data, buf, buf_size);
    u8 *d1buf = data->decisions;

    if (d1) {

      /* copy parent 1 decisions aside, then parse parent 2 */
      u8 *tmp = (u8 *)malloc(d1);
      if (tmp) {

        memcpy(tmp, d1buf, d1);

        u8 *dec2 = NULL;
        size_t d2 = 0;
        size_t asize =
            add_buf_size > MAX_FILE_SIZE_FFMUT ? MAX_FILE_SIZE_FFMUT
                                               : add_buf_size;
        int ok2 = ff_parse(add_buf, asize, &dec2, &d2);

        if (ok2 && dec2 && d2 > 0) {

          /* splice decision files at a random cut point */
          size_t cut1 = 1 + rnd_below(data, d1);
          size_t cut2 = rnd_below(data, d2);
          size_t out = cut1 + (d2 - cut2);

          u8 *spliced = (u8 *)malloc(out ? out : 1);
          if (spliced) {

            memcpy(spliced, tmp, cut1);
            memcpy(spliced + cut1, dec2 + cut2, d2 - cut2);

            size_t gen_size =
                generate_from_decisions(data, spliced, out, max_size);
            free(spliced);

            if (gen_size) {

              free(tmp);
              data->n_splice++;
              set_desc(data, "ffmut-decision-splice[%zu+%zu]",
                       "png");
              *out_buf = data->out_buf;
              return gen_size;

            }

          }

        }

        free(tmp);

      }

    }

    /* fall through */

  }

  /* (c) decision-space mutation of the parent (default path) */
  if (choice >= data->p_random + data->p_direct) {

    size_t dsize = parse_to_decisions(data, buf, buf_size);

    if (dsize) {

      u8 *dec = data->decisions;
      for (u32 i = 0; i < data->decision_muts; ++i) {

        size_t pos = rnd_below(data, dsize);
        switch (rnd_below(data, 3)) {

          case 0:
            dec[pos] ^= (u8)(1 << rnd_below(data, 8));
            break;
          case 1:
            dec[pos] = (u8)random();
            break;
          default:
            dec[pos] += (u8)(1 + rnd_below(data, 35));
            break;

        }

      }

      size_t gen_size =
          generate_from_decisions(data, dec, dsize, max_size);
      if (gen_size) {

        data->n_decision++;
        set_desc(data, "ffmut-decision-mut[%zu]", "png");
        *out_buf = data->out_buf;
        return gen_size;

      }

      data->n_gen_fail++;

    } else {

      data->n_parse_fail++;

    }

    /* fall through to direct havoc on failure */

  }

  /* (d) plain byte-level havoc fallback */
  size_t havoc_size = direct_havoc(data, buf, buf_size, max_size);
  if (havoc_size) {

    data->n_direct++;
    set_desc(data, "ffmut-direct-havoc[%zu]", "png");
    *out_buf = data->out_buf;
    return havoc_size;

  }

  /* last resort: return parent unchanged */
  set_desc(data, "ffmut-identity", "png");
  *out_buf = buf;
  return buf_size;

}

/* ------------------------------------------------------------------ */
/* 6. afl_custom_describe                                              */
/* ------------------------------------------------------------------ */

extern "C" const char *afl_custom_describe(void *ptr,
                                           size_t max_description_len) {

  ffmutator_t *data = (ffmutator_t *)ptr;
  if (max_description_len == 0) return data->describe_buf;
  return data->describe_buf;

}

/* ------------------------------------------------------------------ */
/* 7. afl_custom_post_process                                          */
/* ------------------------------------------------------------------ */

extern "C" size_t afl_custom_post_process(void *ptr, u8 *buf,
                                          size_t buf_size, u8 **out_buf) {

  ffmutator_t *data = (ffmutator_t *)ptr;

  if (!data->ffgen_mode) {

    /* FFMut: afl_custom_fuzz already produced a binary PNG. */
    *out_buf = buf;
    return buf_size;

  }

  /* FFGen: buf is a FormatFuzzer decision file. Translate to binary. */
  u8 *gen = NULL;
  size_t gen_size = ff_generate(buf, buf_size, &gen);

  if (!gen || gen_size == 0) {

    /* decision file did not yield a file - let AFL++ run the original
       (it will most likely be rejected quickly by the target) */
    *out_buf = buf;
    return buf_size;

  }

  u8 *dst = ensure_post(data, gen_size);
  if (!dst) {

    *out_buf = buf;
    return buf_size;

  }

  memcpy(dst, gen, gen_size);
  data->n_post++;
  *out_buf = dst;
  return gen_size;

}

/* ------------------------------------------------------------------ */
/* 8/9/10. trimming (decision-space trimming)                          */
/* ------------------------------------------------------------------ */

extern "C" int afl_custom_init_trim(void *ptr, u8 *buf, size_t buf_size) {

  ffmutator_t *data = (ffmutator_t *)ptr;

  size_t dsize = parse_to_decisions(data, buf, buf_size);
  if (!dsize) return 0; /* cannot trim what we cannot parse: 0 steps */

  free(data->trim_decisions);
  data->trim_decisions = (u8 *)malloc(dsize);
  if (!data->trim_decisions) return 0;
  memcpy(data->trim_decisions, data->decisions, dsize);
  data->trim_decisions_size = dsize;

  /* keep the parent's binary as ultimate fallback: afl_custom_trim()
     must never return NULL (AFL++ treats it as fatal) */
  if (data->trim_fallback_size < buf_size) {

    u8 *nb = (u8 *)realloc(data->trim_fallback, buf_size);
    if (!nb) return 0;
    data->trim_fallback = nb;
    data->trim_fallback_size = buf_size;

  }
  memcpy(data->trim_fallback, buf, buf_size);

  /* logarithmic schedule: try cutting the decision file to
     1/2, 1/4, 1/8, ... of its size */
  size_t steps = 0;
  for (size_t l = dsize / 2; l >= 16 && steps < 16; l /= 2) ++steps;
  if (steps == 0) steps = 1;

  data->trim_steps = steps;
  data->trim_step = 0;
  data->trim_candidate = dsize / 2;

  return (int)steps;

}

extern "C" size_t afl_custom_trim(void *ptr, u8 **out_buf) {

  ffmutator_t *data = (ffmutator_t *)ptr;

  size_t cut = data->trim_candidate;
  if (cut) {

    size_t gen_size =
        generate_from_decisions(data, data->trim_decisions, cut,
                                MAX_FILE_SIZE_FFMUT);
    if (gen_size) {

      data->n_trim++;
      set_desc(data, "ffmut-trim[decisions:%zu]", "png");
      *out_buf = data->out_buf;
      return gen_size;

    }

  }

  /* generation failed: hand back the last known good binary */
  data->n_trim++;
  set_desc(data, "ffmut-trim[fallback]", "png");
  *out_buf = data->trim_fallback;
  return data->trim_fallback_size ? data->trim_fallback_size : 1;

}

extern "C" int afl_custom_post_trim(void *ptr, unsigned char success) {

  ffmutator_t *data = (ffmutator_t *)ptr;

  if (success) {

    /* accept the cut, try an even shorter decision file next */
    data->trim_step++;
    data->trim_candidate /= 2;
    if (data->trim_step >= data->trim_steps || data->trim_candidate < 16)
      return (int)data->trim_steps;
    return (int)data->trim_step;

  }

  /* cut was too aggressive: restore to the last known good length
     (decision files regrow by doubling) */
  if (data->trim_candidate < data->trim_decisions_size) {

    data->trim_candidate *= 2;
    if (data->trim_candidate > data->trim_decisions_size)
      data->trim_candidate = data->trim_decisions_size;

  }

  return (int)(++data->trim_step >= data->trim_steps ? data->trim_steps
                                                     : data->trim_step);

}

/* ------------------------------------------------------------------ */
/* 11/12. havoc mutation                                               */
/* ------------------------------------------------------------------ */

extern "C" size_t afl_custom_havoc_mutation(void *ptr, u8 *buf,
                                            size_t buf_size, u8 **out_buf,
                                            size_t max_size) {

  ffmutator_t *data = (ffmutator_t *)ptr;

  /* In FFMut mode, let FormatFuzzer do a quick decision-space mutation.
     In FFGen mode the buffer is a decision file already: stack a plain
     byte flip on top of AFL++'s havoc. */
  if (!data->ffgen_mode && buf_size > 8 && (random() % 100) < 30) {

    size_t dsize = parse_to_decisions(data, buf, buf_size);
    if (dsize) {

      u8 *dec = data->decisions;
      for (u32 i = 0; i < 2; ++i) {

        size_t pos = rnd_below(data, dsize);
        dec[pos] ^= (u8)(1 << rnd_below(data, 8));

      }

      size_t gen_size =
          generate_from_decisions(data, dec, dsize, max_size);
      if (gen_size) {

        data->n_decision++;
        set_desc(data, "ffmut-havoc-decision[%zu]", "png");
        *out_buf = data->out_buf;
        return gen_size;

      }

    }

  }

  *out_buf = buf;
  if (buf_size <= 1) return buf_size;
  size_t pos = rnd_below(data, buf_size);
  buf[pos] ^= (u8)(1 << rnd_below(data, 8));
  data->n_direct++;
  set_desc(data, "ffmut-havoc-bitflip[%zu]", "png");
  return buf_size;

}

extern "C" unsigned char afl_custom_havoc_mutation_probability(void *ptr) {

  (void)ptr;
  return 5; /* 5 %, same as AFL++ default */

}

/* ------------------------------------------------------------------ */
/* 13. afl_custom_queue_get                                            */
/* ------------------------------------------------------------------ */

extern "C" unsigned char afl_custom_queue_get(void *ptr,
                                              const u8 *filename) {

  (void)ptr;
  (void)filename;
  /* fuzz every queue entry */
  return 1;

}

/* ------------------------------------------------------------------ */
/* 14. afl_custom_fuzz_send                                            */
/* ------------------------------------------------------------------ */

extern "C" void afl_custom_fuzz_send(void *ptr, const u8 *buf,
                                     size_t buf_size) {

  ffmutator_t *data = (ffmutator_t *)ptr;
  data->n_send++;
  set_desc(data, "ffmut-send[%zu]", "png");

  /* AFL++ calls this hook INSTEAD of its own write_to_testcase() when
     the symbol is exported and AFL_CUSTOM_MUTATOR_LATE_SEND is not set,
     so we faithfully perform the write here (mirroring
     afl_fsrv_write_to_testcase() for the shmem and file/fd cases).
     With AFL_CUSTOM_MUTATOR_LATE_SEND=1 AFL++ instead hands the buffer
     to us via fsrv->custom_input after the target restarted (line
     ~2794/2886 in afl-forkserver.c) - that path needs no write here. */
  afl_forkserver_t *fsrv = &data->afl->fsrv;

#ifdef __linux__
  if (unlikely(fsrv->nyx_mode)) {

    /* nyx input injection is handled by the fsrv itself */
    return;

  }
#endif

  if (likely(fsrv->use_shmem_fuzz)) {

    if (unlikely(buf_size > MAX_FILE)) buf_size = MAX_FILE;
    *fsrv->shmem_fuzz_len = (u32)buf_size;
    memcpy(fsrv->shmem_fuzz, buf, buf_size);

  } else {

    s32 fd = fsrv->out_fd;

    if (!fsrv->use_stdin && fsrv->out_file) {

      if (unlikely(fsrv->no_unlink)) {

        fd = open((const char *)fsrv->out_file, O_WRONLY | O_CREAT | O_TRUNC, fsrv->perm);

      } else {

        unlink((const char *)fsrv->out_file); /* ignore errors */
        fd = open((const char *)fsrv->out_file, O_WRONLY | O_CREAT | O_EXCL, fsrv->perm);

      }

      if (fd < 0) {

        fprintf(stderr, "ffmut: unable to create '%s'\n", fsrv->out_file);
        return;

      }

    } else if (unlikely(fd <= 0)) {

      fprintf(stderr, "ffmut: nowhere to write testcase to\n");
      return;

    } else {

      lseek(fd, 0, SEEK_SET);

    }

    /* ck_write equivalent: full write or die trying */
    ssize_t off = 0;
    while ((size_t)off < buf_size) {

      ssize_t w = write(fd, buf + off, buf_size - off);
      if (w < 0) break;
      off += w;

    }

    if (fsrv->use_stdin) {

      ftruncate(fd, buf_size);
      lseek(fd, 0, SEEK_SET);

    } else {

      close(fd);

    }

  }

}

/* ------------------------------------------------------------------ */
/* 15. afl_custom_queue_new_entry                                      */
/* ------------------------------------------------------------------ */

extern "C" u8 afl_custom_queue_new_entry(void *ptr,
                                         const u8 *filename_new_queue,
                                         const u8 *filename_orig_queue) {

  ffmutator_t *data = (ffmutator_t *)ptr;
  data->n_queue++;
  (void)filename_new_queue;
  (void)filename_orig_queue;
  /* we do not modify the new queue entry on disk */
  return 0;

}

/* ------------------------------------------------------------------ */
/* 16. afl_custom_deinit                                               */
/* ------------------------------------------------------------------ */

extern "C" void afl_custom_deinit(void *ptr) {

  ffmutator_t *data = (ffmutator_t *)ptr;
  if (!data) return;

  free(data->out_buf);
  free(data->post_buf);
  free(data->decisions);
  free(data->trim_decisions);
  free(data->trim_fallback);
  free(data);

}
