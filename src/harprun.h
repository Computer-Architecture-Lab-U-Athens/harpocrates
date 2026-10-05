/* harprun: execute thousands of Harpocrates instruction sequences back-to-back in one
 * process and collect a signature of the architectural end state after each one.
 *
 * Pack file format (little-endian, version 1). All offsets are from the file start.
 * A pack contains native code that the runner executes with its own privileges: load only
 * packs you trust. The loader validates structure, it is not a sandbox.
 * The runner maps the code arena at code_base and the data and stack regions at the
 * fixed addresses recorded in the header, so address-dependent results (RIP-relative
 * LEA, pointers stored to memory) are identical on every core and every machine.
 */
#ifndef HARPRUN_H
#define HARPRUN_H

#include <stdint.h>

#define HPK_MAGIC "HARPPACK"
#define HPK_VERSION 1u

#define HPK_TEST_FLAG_LOOPS 0x1u /* code contains its own repetition loop (informational) */

struct hpk_header {
    char magic[8];
    uint32_t version;
    uint32_t n_tests;
    uint64_t data_base;   /* fixed address of the data region */
    uint64_t data_size;   /* bytes mapped; images are at most this long, rest is zero */
    uint64_t data_hash;   /* bytes of the data region included in the signature */
    uint64_t stack_base;  /* fixed address of the sequence stack region */
    uint64_t stack_size;  /* RSP starts at stack_base + stack_size - 64 */
    uint64_t code_base;   /* fixed address of the code arena */
    uint64_t code_slot;   /* bytes per test slot; test i is linked at code_base + i*code_slot */
    uint64_t n_images;
    uint64_t images_off;  /* array of hpk_image */
    uint64_t tests_off;   /* array of hpk_test */
    uint64_t strings_off; /* NUL-terminated ids */
    uint64_t blobs_off;   /* raw bytes */
    uint64_t file_size;
    uint32_t sig_version; /* signature version of the expected_sig fields; 0 when the pack has none */
    uint8_t reserved[28];
};

struct hpk_image {
    uint64_t blob_off;
    uint64_t size;
};

struct hpk_test {
    uint64_t id_off;        /* relative to strings_off */
    uint64_t code_off;      /* relative to blobs_off */
    uint32_t code_size;
    uint32_t image_index;
    uint64_t expected_sig;  /* 0 = none */
    uint32_t flags;
    uint32_t reserved;
};

/* Captured end state, filled by the exit trampoline or the signal handler. */
struct harp_capture {
    uint64_t gpr[16];       /* rax rbx rcx rdx rsi rdi rbp rsp r8..r15 */
    uint64_t rflags;
    uint64_t rip;           /* only meaningful for signal exits */
    uint32_t exit_kind;     /* 0 normal, 1 signal, 2 timeout */
    uint32_t signum;
    int32_t sig_code;
    uint32_t pad;
    uint64_t sig_addr;
};

enum { GPR_RAX, GPR_RBX, GPR_RCX, GPR_RDX, GPR_RSI, GPR_RDI, GPR_RBP, GPR_RSP,
       GPR_R8, GPR_R9, GPR_R10, GPR_R11, GPR_R12, GPR_R13, GPR_R14, GPR_R15 };

/* Shared with exec_x86_64.S; layout must match the offsets there. */
struct harp_exec_state {
    uint64_t entry;         /* address to jump to */
    uint64_t host_rsp;      /* runner stack pointer while a sequence runs */
    uint64_t seq_rsp;       /* baseline RSP for the sequence */
    uint64_t xsave_mask;    /* EDX:EAX for xsave64/xrstor64, 0 => fxsave64/fxrstor64 */
    uint32_t mxcsr_default; /* 0x1f80, reloaded for the host by harp_return */
    uint32_t pad;
    uint64_t inside;        /* nonzero while a sequence runs */
    struct harp_capture cap;
};

extern struct harp_exec_state harp_state;
extern uint8_t harp_xsave_area[];      /* 64-byte aligned, HARP_XSAVE_SIZE bytes */
extern uint8_t harp_init_image[];      /* same size; zero header, FCW 0x37F, MXCSR 0x1F80 */
extern uint8_t harp_exit_stack_top[];  /* top of the dedicated exit stack */

#define HARP_XSAVE_SIZE 4096

void harp_run(uint64_t entry);        /* runs the sequence; returns after it exits */
void harp_exit_trampoline(void);      /* target of the jump appended to every sequence */
void harp_exit_from_signal(void);     /* resume point installed by the signal handler */

/* ---- runner internals shared between harprun.c and the voting mode ------------------ */

#include <stdio.h>

#define MAX_ONLY 4096

enum exit_code { EXIT_OK = 0,           /* agreement (voting) or a clean observation/reference match */
                 EXIT_USAGE = 1,
                 EXIT_UNSUPPORTED = 2,  /* CPU, pack version or pack structure cannot be run */
                 EXIT_MISMATCH = 3,     /* disagreement, instability or reference mismatch; wins over partial */
                 EXIT_INTERNAL = 4,     /* internal or output error */
                 EXIT_PARTIAL = 5 };    /* incomplete run or insufficient voting evidence, no finding */

struct options {
    const char *pack_path;
    int cpu;                /* single-core mode: CPU to pin to, -1 = do not pin */
    const char *cpus;       /* voting mode: "all" or a list; NULL = single-core mode */
    int repeats;            /* executions per test and cycle; comparable results must agree */
    int rounds;             /* voting mode: passes over the selected tests */
    int group_none;         /* voting mode: one group, ignore core types */
    int tick_ms;            /* per-execution CPU allowance is twice this value; polling is at most 100 ms */
    double max_seconds;
    double worker_wait_seconds; /* voting: wall allowance for startup and missing worker progress */
    int json;
    int brief;
    int check;              /* validate and load the pack, do not run it */
    const char *json_file;  /* NULL: automatic JSON file (or stdout for text); "-": stdout; otherwise an explicit path */
    const char *dump_id;
    uint64_t flags_mask;
    const char *only[MAX_ONLY];
    int n_only;
};

struct pack {
    const uint8_t *map;
    size_t map_size;
    const struct hpk_header *h;
    const struct hpk_image *images;
    const struct hpk_test *tests;
    const char *strings;
    const uint8_t *blobs;
};

struct result {
    uint64_t sig;
    uint64_t comp[6];       /* gpr flags vec mem stack exit */
    uint32_t exit_kind;     /* 0 normal, 1 signal, 2 timeout */
    uint32_t signum;
    int32_t sig_code;
    uint32_t vec_full;      /* signal exits: 1 when the extended vector state was captured from the signal frame */
    uint64_t sig_addr;
    uint64_t rip_off;
    uint32_t runs;
    uint32_t unstable;      /* comparable repeats differing from the first comparable result */
    uint32_t timeouts;      /* included in runs, excluded from comparisons */
    uint32_t first_timeout_repeat; /* zero-based; valid when timeouts is nonzero */
    uint64_t timeout_cpu_ns, timeout_wall_ns; /* elapsed time at the first timeout */
    uint64_t ns_min, ns_max, ns_sum, cycle_sum;
    int checked, match;
};

void die(const char *fmt, ...) __attribute__((noreturn, format(printf, 1, 2)));        /* exit 4 */
void die_usage(const char *fmt, ...) __attribute__((noreturn, format(printf, 1, 2)));  /* exit 1 */
uint64_t now_ns(void);
const char *test_id(const struct pack *p, uint32_t i);
/* Per process: 2*tick_ms of thread CPU time per execution, separate wall deadline.
 * SIGALRM polls at min(tick_ms, 100 ms), or at most 10 ms with a wall deadline.
 * The timer is not inherited by fork; delayed delivery can enforce limits late. */
void start_watchdog(int tick_ms, uint64_t deadline_ns);

/* One execution. Bumps *harp_heartbeat first when it is set (workers point it into the shared table). */
uint64_t run_once(const struct pack *p, uint32_t index, struct result *r, uint64_t *cycle_ns);
extern volatile uint64_t *harp_heartbeat;

/* One cycle of a test: the first comparable result is representative; only differing
 * comparable repeats count as unstable. If all repeats time out, the first timeout is
 * representative. Stops between executions when *stop is nonzero, or at the deadline
 * configured by start_watchdog. Returns 1 on interruption, keeping only completed executions in
 * r->runs (a budget-cancelled snapshot is not a hardware outcome); returns 0 when complete. */
int harp_cycle(const struct options *o, const struct pack *p, uint32_t index, struct result *r,
               const volatile uint64_t *stop, uint64_t deadline_ns);

/* "all" or "0-3,8,10-11" -> unique CPUs of this process's affinity mask; exits 1 on anything else. */
int parse_cpu_list(const char *spec, int **cpus);
uint64_t harp_core_type(void);          /* CPUID leaf 0x1A of the current CPU: 0x40 core, 0x20 atom, 0 unknown */
const char *harp_core_type_name(uint64_t type);

void json_escape(FILE *f, const char *s);
void report_header(FILE *out, const struct options *o, const struct pack *p, const char *mode);  /* common JSON fields */
FILE *out_open(const struct options *o);
void out_close(FILE *f);                /* flushes and closes; exits 4 if anything could not be written */
/* Finish the detailed report before a human footer. Saved reports use stdout for the footer;
 * stdout JSON uses stderr; text output keeps the same stream. Close the returned stream last. */
FILE *summary_output(FILE *report, const struct options *o);
void summary_status(FILE *out, const struct options *o, const char *status, int partial, uint64_t elapsed_ns);
void summary_saved(FILE *out, const struct options *o);

/* Voting mode (--cpus). */
int orchestrate(const struct options *o, const struct pack *p, const uint32_t *sel, uint32_t n_sel);


#endif
