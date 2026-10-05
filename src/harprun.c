/* harprun: back-to-back execution of Harpocrates instruction sequences with end-state
 * signatures. The pack format is in harprun.h.
 */
#define _GNU_SOURCE
#include "harprun.h"

#include <cpuid.h>
#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <ucontext.h>
#include <unistd.h>

#include "hash.h"

#ifndef HARPRUN_VERSION
#define HARPRUN_VERSION "1.0.0"
#endif
#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif

/* RFLAGS bits that are part of the architectural result: CF PF AF ZF SF DF OF. */
#define RFLAGS_MASK_DEFAULT 0xCD5ull
#define SIGSTACK_SIZE 65536
#define STACK_WINDOW 16384ull   /* top of the sequence stack that is always accessible */
#define XSAVE_LEGACY 512
#define XSAVE_EXTENDED 576      /* legacy area + XSAVE header */

static uint64_t rflags_mask = RFLAGS_MASK_DEFAULT;
struct harp_exec_state harp_state __attribute__((aligned(64)));
volatile uint64_t *harp_heartbeat;
static volatile sig_atomic_t deadline_expired, execution_cancelled;
static uint64_t execution_deadline, watchdog_cpu_ns;
/* Signal-shared timestamps must be lock-free: a handler can interrupt their publisher. */
_Static_assert(ATOMIC_LONG_LOCK_FREE == 2 && ATOMIC_LLONG_LOCK_FREE == 2, "64-bit signal timestamps must be lock-free");
static _Atomic uint64_t execution_cpu_start, execution_wall_start;
static _Atomic uint64_t execution_timeout_cpu_ns, execution_timeout_wall_ns;
static uint32_t xsave_size = XSAVE_LEGACY;
static uint32_t comp_off[8], comp_size[8];          /* XSAVE components 2..7: offset and size (CPUID leaf 0xD) */
static volatile uint32_t capture_vec_full;
static uint8_t *alt_sigstack;
static uint64_t stack_base, stack_top;
static volatile uint64_t stack_open;                /* [stack_open, stack_top) is accessible, the rest is PROT_NONE */
static uint64_t *stack_hint;                        /* per test: extent a previous run needed, opened up front */
static uint64_t arena_trampoline;
static uint8_t **image_full;                        /* per image: data_size bytes, zero padded, 64-aligned */

static void vmsg(const char *fmt, va_list ap) {
    fputs("harprun: ", stderr);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
}
void die(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt); vmsg(fmt, ap); va_end(ap);
    exit(EXIT_INTERNAL);
}
void die_usage(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt); vmsg(fmt, ap); va_end(ap);
    fputs("harprun: try --help\n", stderr);
    exit(EXIT_USAGE);
}
static void bad_pack(const char *fmt, ...) __attribute__((noreturn, format(printf, 1, 2)));
static void bad_pack(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    fputs("harprun: invalid pack: ", stderr); vfprintf(stderr, fmt, ap); fputc('\n', stderr);
    va_end(ap);
    exit(EXIT_UNSUPPORTED);
}

uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static uint64_t cpu_now_ns(void) {
    struct timespec ts;
    /* Also used in the signal handler: fail closed without unsafe logging. */
    if (clock_gettime(CLOCK_THREAD_CPUTIME_ID, &ts) != 0) _exit(EXIT_INTERNAL);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

/* ---- CPU features ---------------------------------------------------------- */

/* Baseline image for xrstor64/fxrstor64 and the set of XSAVE components to save. */
static void detect_cpu(void) {
    unsigned a, b, c, d;
    harp_state.mxcsr_default = 0x1f80;
    harp_state.xsave_mask = 0;
    memset(harp_init_image, 0, HARP_XSAVE_SIZE);
    uint16_t fcw = 0x37f;
    memcpy(harp_init_image, &fcw, 2);
    memcpy(harp_init_image + 24, &harp_state.mxcsr_default, 4);
    if (!__get_cpuid(1, &a, &b, &c, &d) || !((c >> 27) & 1)) return; /* no OSXSAVE: FXSAVE path */
    uint32_t xcr0_lo, xcr0_hi;
    __asm__ volatile("xgetbv" : "=a"(xcr0_lo), "=d"(xcr0_hi) : "c"(0));
    uint64_t xcr0 = ((uint64_t)xcr0_hi << 32) | xcr0_lo;
    uint64_t want = xcr0 & 0xE7ull; /* x87 SSE AVX opmask ZMM_Hi256 Hi16_ZMM */
    /* Extent of the requested components only; the size CPUID reports for everything
     * XCR0 enables includes 8 KB of AMX tiles on Sapphire Rapids and later. */
    uint32_t extent = XSAVE_EXTENDED;
    for (int i = 2; i < 8; i++) {
        if (!((want >> i) & 1) || !__get_cpuid_count(0xD, i, &a, &b, &c, &d)) continue;
        comp_size[i] = a; comp_off[i] = b;
        if (b + a > extent) extent = b + a;
    }
    if (extent > HARP_XSAVE_SIZE) {
        fprintf(stderr, "harprun: XSAVE image of %u bytes exceeds the %u-byte area\n", extent, HARP_XSAVE_SIZE);
        exit(EXIT_UNSUPPORTED);
    }
    harp_state.xsave_mask = want;
    xsave_size = extent;
}

uint64_t harp_core_type(void) {
    unsigned a, b, c, d;
    return __get_cpuid_count(0x1A, 0, &a, &b, &c, &d) ? (a >> 24) : 0;
}
const char *harp_core_type_name(uint64_t t) { return t == 0x40 ? "core" : t == 0x20 ? "atom" : "unknown"; }

/* ---- pack loading ---------------------------------------------------------- */

static int in_range(uint64_t off, uint64_t len, uint64_t limit) { return off <= limit && len <= limit - off; }
static int overlap(uint64_t a, uint64_t alen, uint64_t b, uint64_t blen) { return a < b + blen && b < a + alen; }

/* Every offset, size and index is checked before anything is dereferenced or allocated, so a
 * malformed file gives a diagnostic. This is structural validation, not a sandbox: the code in
 * a pack runs natively with the runner's privileges. */
static void load_pack(const char *path, struct pack *p) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) die_usage("cannot open pack %s: %s", path, strerror(errno));
    struct stat st;
    if (fstat(fd, &st) != 0) die("fstat: %s", strerror(errno));
    if (!S_ISREG(st.st_mode)) bad_pack("%s is not a regular file", path);
    if ((uint64_t)st.st_size < sizeof(struct hpk_header)) bad_pack("file smaller than the header");
    p->map_size = (size_t)st.st_size;
    p->map = mmap(NULL, p->map_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (p->map == MAP_FAILED) die("mmap pack: %s", strerror(errno));
    const struct hpk_header *h = p->h = (const struct hpk_header *)p->map;
    const uint64_t fsz = p->map_size;
    if (memcmp(h->magic, HPK_MAGIC, 8) != 0) bad_pack("bad magic");
    if (h->version != HPK_VERSION) bad_pack("unsupported pack version %u", h->version);
    if (h->file_size != fsz) bad_pack("recorded size %llu, actual %llu", (unsigned long long)h->file_size, (unsigned long long)fsz);
    if (h->n_tests < 1 || h->n_tests > (1u << 24)) bad_pack("test count %u", h->n_tests);
    if (h->n_images < 1 || h->n_images > (1u << 24)) bad_pack("image count %llu", (unsigned long long)h->n_images);
    if (h->images_off < sizeof *h || !in_range(h->images_off, h->n_images * sizeof(struct hpk_image), fsz)) bad_pack("image table out of range");
    if (h->tests_off < sizeof *h || !in_range(h->tests_off, (uint64_t)h->n_tests * sizeof(struct hpk_test), fsz)) bad_pack("test table out of range");
    if (h->strings_off < sizeof *h || h->strings_off > h->blobs_off || h->blobs_off > fsz) bad_pack("string or blob section out of range");
    const uint64_t strings_len = h->blobs_off - h->strings_off, blobs_len = fsz - h->blobs_off;
    /* Layout of the three fixed regions. */
    const uint64_t page = 4095, user_top = 1ull << 47;
    if ((h->data_base & page) || (h->stack_base & page) || (h->code_base & page)) bad_pack("region bases must be page aligned");
    if (h->data_size < 1 || h->data_size > (1ull << 30)) bad_pack("data size %llu", (unsigned long long)h->data_size);
    if (h->data_hash > h->data_size) bad_pack("data_hash exceeds data_size");
    if (h->stack_size < 4 * STACK_WINDOW || (h->stack_size & page) || h->stack_size > (1ull << 36)) bad_pack("stack size %llu", (unsigned long long)h->stack_size);
    if (h->code_slot < 32 || (h->code_slot & 15) || h->code_slot > (1ull << 30)) bad_pack("code slot %llu", (unsigned long long)h->code_slot);
    const uint64_t arena = (uint64_t)h->n_tests * h->code_slot + 4096;   /* <= 2^54, no overflow */
    if (arena > (1ull << 31) - 65536) bad_pack("code arena of %llu bytes is beyond the reach of the exit jump", (unsigned long long)arena);
    const uint64_t data_len = (h->data_size + page) & ~page;
    if (h->data_base < 65536 || h->stack_base < 65536 || h->code_base < 65536 ||
        !in_range(h->data_base, data_len, user_top) || !in_range(h->stack_base, h->stack_size, user_top) || !in_range(h->code_base, arena, user_top))
        bad_pack("a region lies outside the user address space");
    if (overlap(h->data_base, data_len, h->stack_base, h->stack_size) || overlap(h->data_base, data_len, h->code_base, arena) ||
        overlap(h->stack_base, h->stack_size, h->code_base, arena))
        bad_pack("regions overlap");
    p->images = (const struct hpk_image *)(p->map + h->images_off);
    p->tests = (const struct hpk_test *)(p->map + h->tests_off);
    p->strings = (const char *)(p->map + h->strings_off);
    p->blobs = p->map + h->blobs_off;
    for (uint64_t i = 0; i < h->n_images; i++) {       /* every image, referenced or not: build_images copies them all */
        if (!in_range(p->images[i].blob_off, p->images[i].size, blobs_len)) bad_pack("image %llu out of range", (unsigned long long)i);
        if (p->images[i].size > h->data_size) bad_pack("image %llu larger than the data region", (unsigned long long)i);
    }
    int references = 0;
    for (uint32_t i = 0; i < h->n_tests; i++) {
        const struct hpk_test *t = &p->tests[i];
        if (t->image_index >= h->n_images) bad_pack("test %u: image index", i);
        if (t->code_size < 1 || (uint64_t)t->code_size + 5 > h->code_slot) bad_pack("test %u: code size %u does not fit the slot", i, t->code_size);
        if (!in_range(t->code_off, t->code_size, blobs_len)) bad_pack("test %u: code out of range", i);
        if (t->id_off >= strings_len || !memchr(p->strings + t->id_off, 0, strings_len - t->id_off)) bad_pack("test %u: id not terminated", i);
        if (!p->strings[t->id_off]) bad_pack("test %u: empty id", i);
        if (t->expected_sig) references = 1;
    }
    if (references && h->sig_version != HARP_SIG_VERSION)
        bad_pack("its reference signatures are version %u, this runner produces version %u; regenerate them", h->sig_version, HARP_SIG_VERSION);
}

const char *test_id(const struct pack *p, uint32_t i) { return p->strings + p->tests[i].id_off; }

static void *map_fixed(uint64_t addr, uint64_t size, int prot, int populate) {
    void *r = mmap((void *)addr, size, prot, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE | (populate ? MAP_POPULATE : 0), -1, 0);
    if (r == MAP_FAILED) die("mmap fixed 0x%llx+0x%llx: %s", (unsigned long long)addr, (unsigned long long)size, strerror(errno));
    if (r != (void *)addr) die("mmap fixed 0x%llx returned another address", (unsigned long long)addr);
    return r;
}

static void build_images(const struct pack *p) {
    const struct hpk_header *h = p->h;
    image_full = calloc(h->n_images, sizeof *image_full);
    if (!image_full) die("calloc images");
    for (uint64_t i = 0; i < h->n_images; i++) {
        uint8_t *buf = aligned_alloc(64, (h->data_size + 63) & ~63ull);
        if (!buf) die("aligned_alloc image");
        memset(buf, 0, h->data_size);
        memcpy(buf, p->blobs + p->images[i].blob_off, p->images[i].size);
        image_full[i] = buf;
    }
}

static void map_regions(const struct pack *p) {
    const struct hpk_header *h = p->h;
    uint64_t arena = (uint64_t)h->n_tests * h->code_slot + 4096;
    arena = (arena + 4095) & ~4095ull;
    uint8_t *code = map_fixed(h->code_base, arena, PROT_READ | PROT_WRITE, 1);
    arena_trampoline = h->code_base + (uint64_t)h->n_tests * h->code_slot;
    for (uint32_t i = 0; i < h->n_tests; i++) {
        const struct hpk_test *t = &p->tests[i];
        uint8_t *slot = code + (uint64_t)i * h->code_slot;
        memcpy(slot, p->blobs + t->code_off, t->code_size);
        /* jmp rel32 to the arena trampoline */
        uint64_t next = h->code_base + (uint64_t)i * h->code_slot + t->code_size + 5;
        int64_t rel = (int64_t)arena_trampoline - (int64_t)next;
        slot[t->code_size] = 0xE9;
        int32_t rel32 = (int32_t)rel;
        memcpy(slot + t->code_size + 1, &rel32, 4);
        /* Fill the rest of the slot with int3 so a runaway into padding traps. */
        memset(slot + t->code_size + 5, 0xCC, h->code_slot - t->code_size - 5);
    }
    /* Trampoline slot: jmp *[rip+0]; .quad harp_exit_trampoline */
    uint8_t *tr = code + (arena_trampoline - h->code_base);
    static const uint8_t jmp_ind[6] = {0xFF, 0x25, 0, 0, 0, 0};
    memcpy(tr, jmp_ind, 6);
    uint64_t target = (uint64_t)(uintptr_t)harp_exit_trampoline;
    memcpy(tr + 6, &target, 8);
    if (mprotect(code, arena, PROT_READ | PROT_EXEC) != 0) die("mprotect code: %s", strerror(errno));
    map_fixed(h->data_base, h->data_size, PROT_READ | PROT_WRITE, 1);
    /* The sequence stack: only a window at the top is accessible. The rest is PROT_NONE and is
     * opened on demand by the fault handler, so the runner knows how far a sequence reached. */
    stack_base = h->stack_base;
    stack_top = h->stack_base + h->stack_size;
    map_fixed(stack_base, h->stack_size, PROT_NONE, 0);
    stack_open = stack_top - STACK_WINDOW;
    if (mprotect((void *)(uintptr_t)stack_open, STACK_WINDOW, PROT_READ | PROT_WRITE) != 0) die("mprotect stack: %s", strerror(errno));
    memset((void *)(uintptr_t)stack_open, 0, STACK_WINDOW);
    stack_hint = calloc(h->n_tests, sizeof *stack_hint);
    if (!stack_hint) die("calloc stack hints");
}

/* ---- signals --------------------------------------------------------------- */

/* Vector and x87 state at a fault, from the kernel's signal frame: the 512-byte legacy image and,
 * when the frame carries a valid XSAVE extension, the components the runner asked for. */
static void capture_vector(const ucontext_t *uc) {
    const uint8_t *fp = (const uint8_t *)uc->uc_mcontext.fpregs;
    capture_vec_full = 0;
    if (!fp) return;
    memcpy(harp_xsave_area, fp, XSAVE_LEGACY);
    if (!harp_state.xsave_mask || xsave_size <= XSAVE_EXTENDED) { capture_vec_full = 1; return; } /* nothing beyond x87/SSE to capture */
    uint32_t magic1, extended_size, xstate_size, magic2;
    uint64_t frame_features, frame_bv;
    memcpy(&magic1, fp + 464, 4);                   /* struct _fpx_sw_bytes in the reserved tail of the legacy area */
    memcpy(&extended_size, fp + 468, 4);
    memcpy(&frame_features, fp + 472, 8);
    memcpy(&xstate_size, fp + 480, 4);
    if (magic1 != 0x46505853u || xstate_size < XSAVE_EXTENDED || xstate_size > 65536 || extended_size < xstate_size + 4) return;
    memcpy(&magic2, fp + xstate_size, 4);
    if (magic2 != 0x46505845u) return;
    memcpy(&frame_bv, fp + XSAVE_LEGACY, 8);        /* XSTATE_BV: components that are not in their initial configuration */
    for (int i = 2; i < 8; i++) {
        if (!((harp_state.xsave_mask >> i) & 1)) continue;
        if (!((frame_features >> i) & 1) || (uint64_t)comp_off[i] + comp_size[i] > xstate_size) return; /* not in this frame */
        if ((frame_bv >> i) & 1) memcpy(harp_xsave_area + comp_off[i], fp + comp_off[i], comp_size[i]);
        /* else initial configuration: the area was zeroed before the run */
    }
    capture_vec_full = 1;
}

static void capture_from_ucontext(const ucontext_t *uc, const siginfo_t *si, uint32_t kind) {
    const greg_t *g = uc->uc_mcontext.gregs;
    struct harp_capture *c = &harp_state.cap;
    c->gpr[GPR_RAX] = (uint64_t)g[REG_RAX]; c->gpr[GPR_RBX] = (uint64_t)g[REG_RBX];
    c->gpr[GPR_RCX] = (uint64_t)g[REG_RCX]; c->gpr[GPR_RDX] = (uint64_t)g[REG_RDX];
    c->gpr[GPR_RSI] = (uint64_t)g[REG_RSI]; c->gpr[GPR_RDI] = (uint64_t)g[REG_RDI];
    c->gpr[GPR_RBP] = (uint64_t)g[REG_RBP]; c->gpr[GPR_RSP] = (uint64_t)g[REG_RSP];
    c->gpr[GPR_R8] = (uint64_t)g[REG_R8];   c->gpr[GPR_R9] = (uint64_t)g[REG_R9];
    c->gpr[GPR_R10] = (uint64_t)g[REG_R10]; c->gpr[GPR_R11] = (uint64_t)g[REG_R11];
    c->gpr[GPR_R12] = (uint64_t)g[REG_R12]; c->gpr[GPR_R13] = (uint64_t)g[REG_R13];
    c->gpr[GPR_R14] = (uint64_t)g[REG_R14]; c->gpr[GPR_R15] = (uint64_t)g[REG_R15];
    c->rflags = (uint64_t)g[REG_EFL];
    c->rip = (uint64_t)g[REG_RIP];
    c->exit_kind = kind;
    c->signum = (uint32_t)si->si_signo;
    c->sig_code = si->si_code;
    c->sig_addr = (kind == 1 && (si->si_signo == SIGSEGV || si->si_signo == SIGBUS)) ? (uint64_t)(uintptr_t)si->si_addr : 0;
    capture_vector(uc);
}

static void divert_to_runner(ucontext_t *uc) {
    uc->uc_mcontext.gregs[REG_RIP] = (greg_t)(uintptr_t)harp_exit_from_signal;
    uc->uc_mcontext.gregs[REG_RSP] = (greg_t)(uintptr_t)harp_exit_stack_top;
    uc->uc_mcontext.gregs[REG_EFL] &= ~0x100ll; /* clear TF */
}

/* An access below the open part of the sequence stack: open more (doubling, so a deep stack costs
 * a handful of faults) and let the instruction run again. Anything else is a real fault. */
static int grow_stack(uint64_t addr) {
    if (addr < stack_base || addr >= stack_open) return 0;
    uint64_t extent = stack_top - stack_open, need = stack_top - (addr & ~4095ull);
    while (extent < need) extent *= 2;
    if (extent > stack_top - stack_base) extent = stack_top - stack_base;
    uint64_t lo = stack_top - extent;
    if (mprotect((void *)(uintptr_t)lo, stack_open - lo, PROT_READ | PROT_WRITE) != 0) return 0;
    stack_open = lo;
    return 1;
}

static void fault_handler(int sig, siginfo_t *si, void *ucv) {
    ucontext_t *uc = ucv;
    if (!harp_state.inside) {
        /* Not inside a sequence: this is a runner bug. Crash loudly. */
        signal(sig, SIG_DFL);
        raise(sig);
        return;
    }
    if (sig == SIGSEGV && grow_stack((uint64_t)(uintptr_t)si->si_addr)) return;
    capture_from_ucontext(uc, si, 1);
    divert_to_runner(uc);
}

static void alarm_handler(int sig, siginfo_t *si, void *ucv) {
    (void)sig;
    if (!watchdog_cpu_ns) return; /* an external alarm can precede timer initialization */
    ucontext_t *uc = ucv;
    int saved_errno = errno;
    uint64_t now = now_ns();
    errno = saved_errno;
    if (execution_deadline && now >= execution_deadline) {
        deadline_expired = 1;
        if (harp_state.inside) {
            execution_cancelled = 1;
            capture_from_ucontext(uc, si, 2);
            divert_to_runner(uc);
        }
        return;
    }
    if (!harp_state.inside) return;
    uint64_t cpu_elapsed = cpu_now_ns() - atomic_load_explicit(&execution_cpu_start, memory_order_relaxed);
    errno = saved_errno;
    if (cpu_elapsed >= watchdog_cpu_ns) {
        atomic_store_explicit(&execution_timeout_cpu_ns, cpu_elapsed, memory_order_relaxed);
        atomic_store_explicit(&execution_timeout_wall_ns,
                              now - atomic_load_explicit(&execution_wall_start, memory_order_relaxed), memory_order_relaxed);
        capture_from_ucontext(uc, si, 2);
        divert_to_runner(uc);
    }
}

static void install_signals(void) {
    alt_sigstack = malloc(SIGSTACK_SIZE);
    if (!alt_sigstack) die("malloc alt_sigstack");
    stack_t ss = {.ss_sp = alt_sigstack, .ss_size = SIGSTACK_SIZE, .ss_flags = 0};
    if (sigaltstack(&ss, NULL) != 0) die("sigaltstack: %s", strerror(errno));
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = fault_handler;
    sa.sa_flags = SA_SIGINFO | SA_ONSTACK | SA_NODEFER;
    sigemptyset(&sa.sa_mask);
    /* A deadline must not divert host code while a fault handler captures guest state. */
    sigaddset(&sa.sa_mask, SIGALRM);
    int sigs[] = {SIGSEGV, SIGBUS, SIGILL, SIGFPE, SIGTRAP};
    for (size_t i = 0; i < sizeof sigs / sizeof sigs[0]; i++)
        if (sigaction(sigs[i], &sa, NULL) != 0) die("sigaction: %s", strerror(errno));
    sa.sa_sigaction = alarm_handler;
    sa.sa_flags = SA_SIGINFO | SA_ONSTACK | SA_RESTART;
    if (sigaction(SIGALRM, &sa, NULL) != 0) die("sigaction alarm: %s", strerror(errno));
}

void start_watchdog(int tick_ms, uint64_t deadline_ns) {
    execution_deadline = deadline_ns;
    deadline_expired = execution_cancelled = 0;
    watchdog_cpu_ns = 2ull * (uint64_t)tick_ms * 1000000ull;
    /* SIGALRM is only a wakeup: scheduling delays consume no execution CPU budget.
     * Periodic delivery also covers a deadline arriving just before guest entry. */
    int interval_ms = tick_ms > 100 ? 100 : tick_ms;
    if (deadline_ns && interval_ms > 10) interval_ms = 10;
    struct itimerval it = {.it_interval = {interval_ms / 1000, (interval_ms % 1000) * 1000},
                           .it_value = {interval_ms / 1000, (interval_ms % 1000) * 1000}};
    if (setitimer(ITIMER_REAL, &it, NULL) != 0) die("setitimer: %s", strerror(errno));
}

/* ---- one execution --------------------------------------------------------- */

/* Restore the data image, zero the XSAVE area, place the baseline RSP and open the part of the
 * stack this test is known to need. The stack itself is all zero here: stack_settle() left it so. */
static void reset_state(const struct pack *p, uint32_t index) {
    const struct hpk_header *h = p->h;
    memcpy((void *)(uintptr_t)h->data_base, image_full[p->tests[index].image_index], h->data_size);
    memset(harp_xsave_area, 0, xsave_size);
    harp_state.seq_rsp = stack_top - 64;
    if (stack_hint[index] > stack_top - stack_open) {
        uint64_t lo = stack_top - stack_hint[index];
        if (mprotect((void *)(uintptr_t)lo, stack_open - lo, PROT_READ | PROT_WRITE) != 0) die("mprotect stack: %s", strerror(errno));
        stack_open = lo;
    }
}

/* After a run: hash what the sequence left in the stack region, zero it, and close the region
 * again. Only the opened part can have been touched; below it the region is still zero, and the
 * hash is that of the whole region's content (everything below the lowest nonzero byte is zero,
 * so the result does not depend on how much happened to be open). */
static uint64_t stack_settle(uint32_t index) {
    const uint64_t *w = (const uint64_t *)(uintptr_t)stack_open, *end = (const uint64_t *)(uintptr_t)stack_top;
    while (w < end && *w == 0) w++;
    uint64_t lo = (uint64_t)(uintptr_t)w & ~63ull;
    if (lo < stack_open) lo = stack_open;
    uint64_t hash = harp_hash_combine(stack_top - lo, harp_hash64(0x05, (const void *)(uintptr_t)lo, stack_top - lo));
    memset((void *)(uintptr_t)lo, 0, stack_top - lo);
    uint64_t extent = stack_top - stack_open;
    if (extent > stack_hint[index]) stack_hint[index] = extent;
    if (extent > STACK_WINDOW) {
        if (mprotect((void *)(uintptr_t)stack_open, extent - STACK_WINDOW, PROT_NONE) != 0) die("mprotect stack: %s", strerror(errno));
        stack_open = stack_top - STACK_WINDOW;
    }
    return hash;
}

static void signature(const struct pack *p, uint32_t index, struct result *r) {
    const struct hpk_header *h = p->h;
    const struct harp_capture *c = &harp_state.cap;
    r->comp[0] = harp_hash64(0x01, c->gpr, sizeof c->gpr);
    uint64_t flags = c->rflags & rflags_mask;
    r->comp[1] = harp_hash64(0x02, &flags, sizeof flags);
    /* Vector/x87 state: the legacy image without x87 FIP/FDP (bytes 8..23), MXCSR_MASK (28..31) and
     * the software-reserved tail (464..511, where the kernel describes a signal frame); then the
     * extended components, on a normal exit or when the signal frame supplied them. */
    uint8_t legacy[XSAVE_LEGACY];
    memcpy(legacy, harp_xsave_area, XSAVE_LEGACY);
    memset(legacy + 8, 0, 16);
    memset(legacy + 28, 0, 4);
    memset(legacy + 464, 0, 48);
    r->vec_full = c->exit_kind == 1 ? capture_vec_full : 1;
    uint64_t hv = harp_hash64(0x03, legacy, XSAVE_LEGACY);
    if (harp_state.xsave_mask && xsave_size > XSAVE_EXTENDED && (c->exit_kind == 0 || (c->exit_kind == 1 && r->vec_full)))
        hv = harp_hash_combine(hv, harp_hash64(0x33, harp_xsave_area + XSAVE_EXTENDED, xsave_size - XSAVE_EXTENDED));
    r->comp[2] = hv;
    r->comp[3] = harp_hash64(0x04, (const void *)(uintptr_t)h->data_base, h->data_hash);
    uint64_t rsp = c->gpr[GPR_RSP];
    r->comp[4] = harp_hash_combine(harp_hash64(0x05, &rsp, sizeof rsp), stack_settle(index));
    if (c->exit_kind) {
        uint64_t slot = h->code_base + (uint64_t)index * h->code_slot;
        uint64_t off = c->rip >= slot && c->rip < slot + h->code_slot ? c->rip - slot : UINT64_MAX;
        uint64_t rec[5] = {c->exit_kind, c->signum, (uint64_t)c->sig_code, c->sig_addr, off};
        r->comp[5] = harp_hash64(0x06, rec, sizeof rec);
        r->exit_kind = c->exit_kind; r->signum = c->signum; r->sig_code = c->sig_code;
        r->sig_addr = c->sig_addr; r->rip_off = off;
    } else {
        r->comp[5] = 0;
    }
    if (c->exit_kind == 2) {
        /* A runaway was interrupted at an arbitrary point: only the outcome is meaningful. */
        uint64_t rec = 2;
        for (int i = 0; i < 5; i++) r->comp[i] = 0;
        r->comp[5] = harp_hash64(0x06, &rec, sizeof rec);
    }
    uint64_t s = 0x9E3779B97F4A7C15ull;
    for (int i = 0; i < 6; i++) s = harp_hash_combine(s, r->comp[i]);
    r->sig = s;
}

uint64_t run_once(const struct pack *p, uint32_t index, struct result *r, uint64_t *cycle_ns) {
    if (harp_heartbeat) __atomic_fetch_add(harp_heartbeat, 1, __ATOMIC_RELEASE);
    uint64_t c0 = now_ns();
    memset(r, 0, sizeof *r);
    execution_cancelled = 0;
    reset_state(p, index);
    if (execution_deadline && (deadline_expired || now_ns() >= execution_deadline)) {
        deadline_expired = execution_cancelled = 1;
        *cycle_ns = now_ns() - c0;
        return 0;
    }
    uint64_t t0 = now_ns();
    atomic_store_explicit(&execution_wall_start, t0, memory_order_relaxed);
    atomic_store_explicit(&execution_timeout_cpu_ns, 0, memory_order_relaxed);
    atomic_store_explicit(&execution_timeout_wall_ns, 0, memory_order_relaxed);
    atomic_store_explicit(&execution_cpu_start, cpu_now_ns(), memory_order_relaxed);
    harp_run(p->h->code_base + (uint64_t)index * p->h->code_slot);
    uint64_t t1 = now_ns();
    if (execution_cancelled) {
        *cycle_ns = t1 - c0;
        return t1 - t0;
    }
    signature(p, index, r);
    if (r->exit_kind == 2) {
        r->timeouts = 1;
        r->timeout_cpu_ns = atomic_load_explicit(&execution_timeout_cpu_ns, memory_order_relaxed);
        r->timeout_wall_ns = atomic_load_explicit(&execution_timeout_wall_ns, memory_order_relaxed);
    }
    uint64_t t2 = now_ns();
    *cycle_ns = t2 - c0;
    return t1 - t0;
}

int harp_cycle(const struct options *o, const struct pack *p, uint32_t index, struct result *r,
               const volatile uint64_t *stop, uint64_t deadline_ns) {
    struct result tmp;
    uint64_t cyc;
    memset(r, 0, sizeof *r);
#define INTERRUPTED() ((stop && __atomic_load_n(stop, __ATOMIC_ACQUIRE)) || (deadline_ns && (deadline_expired || now_ns() >= deadline_ns)))
    uint32_t runs = 0, timeouts = 0, unstable = 0, first_timeout_repeat = 0;
    uint64_t ns_min = 0, ns_max = 0, ns_sum = 0, cycle_sum = 0;
    uint64_t timeout_cpu_ns = 0, timeout_wall_ns = 0;
    for (int k = 0; k < o->repeats; k++) {
        if (INTERRUPTED()) return 1;
        uint64_t dt = run_once(p, index, &tmp, &cyc);
        /* A budget interruption is not a hardware outcome. Keep earlier repeats,
         * but do not vote on this arbitrary snapshot or invent an instability. */
        if (execution_cancelled) return 1;
        /* Timeout snapshots are not computed results. Preserve the first comparable
         * result even if earlier repeats timed out, and compare only comparable repeats. */
        if (!tmp.timeouts && runs > timeouts && tmp.sig != r->sig) unstable++;
        if (!runs || (runs == timeouts && !tmp.timeouts)) *r = tmp;
        if (tmp.timeouts) {
            if (!timeouts) {
                first_timeout_repeat = (uint32_t)k;
                timeout_cpu_ns = tmp.timeout_cpu_ns;
                timeout_wall_ns = tmp.timeout_wall_ns;
            }
            timeouts++;
        }
        if (!runs || dt < ns_min) ns_min = dt;
        if (!runs || dt > ns_max) ns_max = dt;
        runs++; ns_sum += dt; cycle_sum += cyc;
        r->runs = runs; r->timeouts = timeouts; r->unstable = unstable;
        r->first_timeout_repeat = first_timeout_repeat;
        r->timeout_cpu_ns = timeout_cpu_ns; r->timeout_wall_ns = timeout_wall_ns;
        r->ns_min = ns_min; r->ns_max = ns_max; r->ns_sum = ns_sum; r->cycle_sum = cycle_sum;
    }
#undef INTERRUPTED
    return 0;
}


/* ---- arguments ------------------------------------------------------------- */

static void usage(FILE *f) {
    fputs("usage: harprun --pack FILE --cpus all|LIST [--rounds N] [--repeats R] [--max-seconds S]\n"
          "               vote: one worker per CPU, agreement checked inside each core design\n"
          "       harprun --pack FILE [--cpu N] [--repeats R] [--max-seconds S] [--dump ID]\n"
          "               one core (default: the CPU the run starts on): signatures are observed, and checked\n"
          "               only against references the pack carries\n"
          "options for both modes:\n"
          "  --only ID            run only this test (repeatable)\n"
          "  --repeats R          executions per test and pass; comparable results must agree (default 1)\n"
          "  --max-seconds S      stop after S seconds and report a partial result\n"
          "  --output json|text   default: save JSON in ./harprun-<timestamp>-<unique>.json and print a summary\n"
          "  --json-file PATH     choose the report path; '-' streams JSON to stdout (summary on stderr)\n"
          "                      --output text prints detailed text and the summary to stdout\n"
          "  --brief              list only tests and cores that are not clean\n"
          "  --tick-ms T          per-execution CPU allowance is 2*T ms (default T=5000); polls at most 100 ms\n"
          "  --worker-wait-seconds S  voting wall allowance (default 60); must exceed 2*T/1000 seconds\n"
          "  --check              validate and load the pack without running anything\n"
          "advanced:\n"
          "  --flags-mask HEX     RFLAGS bits in the signature (default 0xcd5: CF PF AF ZF SF DF OF)\n"
          "  --group-by auto|none vote inside each core design (default) or across all listed CPUs\n"
          "exit: 0 agreement or clean observation, 1 usage, 2 unsupported CPU or pack, 3 disagreement/instability/\n"
          "      reference mismatch, 4 internal or output error, 5 partial run or insufficient voting evidence\n"
          "       harprun --version\n", f);
}

static long arg_long(const char *name, const char *v, long lo, long hi) {
    char *end;
    errno = 0;
    long x = strtol(v, &end, 10);
    if (!*v || *end || errno || x < lo || x > hi) die_usage("%s: '%s' is not a number between %ld and %ld", name, v, lo, hi);
    return x;
}

static void parse_args(int argc, char **argv, struct options *o) {
    memset(o, 0, sizeof *o);
    o->cpu = -1; o->repeats = 1; o->rounds = 1; o->json = 1; o->tick_ms = 5000; o->worker_wait_seconds = 60; o->flags_mask = RFLAGS_MASK_DEFAULT;
    int have_cpu = 0, have_rounds = 0, have_group = 0;
    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "--version")) { printf("harprun %s\n", HARPRUN_VERSION); out_close(stdout); exit(EXIT_OK); }
        if (!strcmp(a, "--help") || !strcmp(a, "-h")) { usage(stdout); out_close(stdout); exit(EXIT_OK); }
        if (!strcmp(a, "--brief")) { o->brief = 1; continue; }
        if (!strcmp(a, "--check")) { o->check = 1; continue; }
        static const char *valued[] = {"--pack", "--cpu", "--cpus", "--repeats", "--rounds", "--max-seconds", "--only", "--output", "--json-file",
                                       "--dump", "--tick-ms", "--worker-wait-seconds", "--flags-mask", "--group-by",
                                       NULL};
        int known = 0;
        for (int k = 0; valued[k]; k++) known |= !strcmp(a, valued[k]);
        if (!known) die_usage("unknown option '%s'", a);
        if (i + 1 >= argc) die_usage("%s needs a value", a);
        const char *v = argv[++i];
        if (!strcmp(a, "--pack")) o->pack_path = v;
        else if (!strcmp(a, "--cpu")) { o->cpu = (int)arg_long(a, v, 0, CPU_SETSIZE - 1); have_cpu = 1; }
        else if (!strcmp(a, "--cpus")) o->cpus = v;
        else if (!strcmp(a, "--repeats")) o->repeats = (int)arg_long(a, v, 1, 1000000);
        else if (!strcmp(a, "--rounds")) { o->rounds = (int)arg_long(a, v, 1, 1000000000); have_rounds = 1; }
        else if (!strcmp(a, "--tick-ms")) o->tick_ms = (int)arg_long(a, v, 10, 3600000);
        else if (!strcmp(a, "--max-seconds") || !strcmp(a, "--worker-wait-seconds")) {
            char *end;
            errno = 0;
            double seconds = strtod(v, &end);
            if (!*v || *end || errno || !isfinite(seconds) || seconds <= 0 || seconds > 1e9)
                die_usage("%s: '%s' is not a positive number of seconds (maximum 1e9)", a, v);
            if (!strcmp(a, "--max-seconds")) o->max_seconds = seconds;
            else o->worker_wait_seconds = seconds;
        }
        else if (!strcmp(a, "--flags-mask")) {
            char *end;
            errno = 0;
            unsigned long long m = strtoull(v, &end, 16);
            if (!*v || *v == '-' || *v == '+' || *end || errno) die_usage("--flags-mask: '%s' is not a hexadecimal mask", v);
            if (m & ~RFLAGS_MASK_DEFAULT) die_usage("--flags-mask: only the status and direction flags 0x%llx can be selected", RFLAGS_MASK_DEFAULT);
            o->flags_mask = m;
        }
        else if (!strcmp(a, "--json-file")) o->json_file = v;
        else if (!strcmp(a, "--dump")) o->dump_id = v;
        else if (!strcmp(a, "--output")) { if (!strcmp(v, "json")) o->json = 1; else if (!strcmp(v, "text")) o->json = 0; else die_usage("--output: json or text, not '%s'", v); }
        else if (!strcmp(a, "--group-by")) { have_group = 1; if (!strcmp(v, "none")) o->group_none = 1; else if (strcmp(v, "auto")) die_usage("--group-by: auto or none, not '%s'", v); }
        else if (!strcmp(a, "--only")) { if (o->n_only >= MAX_ONLY) die_usage("more than %d --only options", MAX_ONLY); o->only[o->n_only++] = v; }
    }
    if (!o->pack_path) die_usage("--pack is required");
    if (o->cpus && have_cpu) die_usage("--cpu selects single-core mode and --cpus voting mode; give one of them");
    if (o->cpus && o->dump_id) die_usage("--dump works in single-core mode only (use --cpu N --only ID --dump ID)");
    if (!o->cpus && (have_rounds || have_group)) die_usage("--rounds and --group-by belong to voting mode (--cpus)");
    if (o->cpus && o->worker_wait_seconds <= 2.0 * o->tick_ms / 1000.0)
        die_usage("--worker-wait-seconds must exceed the %.9g-second CPU allowance (2 * --tick-ms) in voting mode", 2.0 * o->tick_ms / 1000.0);
}

int parse_cpu_list(const char *spec, int **out) {
    cpu_set_t allowed;
    if (sched_getaffinity(0, sizeof allowed, &allowed) != 0) die("sched_getaffinity: %s", strerror(errno));
    int *cpus = calloc(CPU_SETSIZE, sizeof *cpus);
    unsigned char *seen = calloc(CPU_SETSIZE, 1);
    if (!cpus || !seen) die("calloc");
    int n = 0;
    if (!strcmp(spec, "all")) {
        for (int c = 0; c < CPU_SETSIZE; c++) if (CPU_ISSET(c, &allowed)) cpus[n++] = c;
    } else {
        const char *s = spec;
        if (!*s) die_usage("--cpus: empty list");
        for (;;) {
            char *end;
            if (*s < '0' || *s > '9') die_usage("--cpus: malformed list '%s'", spec);
            errno = 0;
            long lo = strtol(s, &end, 10), hi = lo;
            if (errno || lo >= CPU_SETSIZE) die_usage("--cpus: CPU number out of range in '%s'", spec);
            if (*end == '-') {
                s = end + 1;
                if (*s < '0' || *s > '9') die_usage("--cpus: malformed range in '%s'", spec);
                hi = strtol(s, &end, 10);
                if (errno || hi >= CPU_SETSIZE || hi < lo) die_usage("--cpus: bad range in '%s'", spec);
            }
            for (long c = lo; c <= hi; c++) {
                if (seen[c]) die_usage("--cpus: CPU %ld is listed more than once", c);
                if (!CPU_ISSET(c, &allowed)) die_usage("--cpus: CPU %ld is not available to this process", c);
                seen[c] = 1;
                cpus[n++] = (int)c;
            }
            if (!*end) break;
            if (*end != ',') die_usage("--cpus: malformed list '%s'", spec);
            s = end + 1;
        }
    }
    free(seen);
    if (!n) die_usage("--cpus: no CPU available");
    *out = cpus;
    return n;
}

/* Selected tests in pack order; every --only id must exist. */
static uint32_t *select_tests(const struct options *o, const struct pack *p, uint32_t *n_sel) {
    uint32_t n = p->h->n_tests, k = 0;
    uint32_t *sel = calloc(n, sizeof *sel);
    if (!sel) die("calloc");
    if (!o->n_only) {
        for (uint32_t i = 0; i < n; i++) sel[k++] = i;
    } else {
        unsigned char *want = calloc(n, 1);
        if (!want) die("calloc");
        for (int j = 0; j < o->n_only; j++) {
            uint32_t i = 0;
            while (i < n && strcmp(o->only[j], test_id(p, i))) i++;
            if (i == n) die_usage("--only: the pack has no test '%s'", o->only[j]);
            want[i] = 1;
        }
        for (uint32_t i = 0; i < n; i++) if (want[i]) sel[k++] = i;
        free(want);
    }
    *n_sel = k;
    return sel;
}

/* ---- output ---------------------------------------------------------------- */

void json_escape(FILE *f, const char *s) {
    fputc('"', f);
    for (; *s; s++) {
        unsigned char ch = (unsigned char)*s;
        if (ch == '"' || ch == '\\') { fputc('\\', f); fputc(ch, f); }
        else if (ch < 0x20) fprintf(f, "\\u%04x", ch);
        else fputc(ch, f);
    }
    fputc('"', f);
}

void report_header(FILE *out, const struct options *o, const struct pack *p, const char *mode) {
    fprintf(out, "{\"schema_version\": 1, \"tool\": \"harprun\", \"tool_version\": \"%s\", \"signature_version\": %u, \"mode\": \"%s\", ",
            HARPRUN_VERSION, HARP_SIG_VERSION, mode);
    fprintf(out, "\"pack\": {\"path\": "); json_escape(out, o->pack_path);
    fprintf(out, ", \"n_tests\": %u, \"code_base\": \"%llx\", \"data_base\": \"%llx\", \"data_hash\": %llu}, ", p->h->n_tests,
            (unsigned long long)p->h->code_base, (unsigned long long)p->h->data_base, (unsigned long long)p->h->data_hash);
    fprintf(out, "\"repeats\": %d, \"xsave_mask\": \"%llx\", \"xsave_size\": %u, \"flags_mask\": \"%llx\", \"hash_hw\": %s, ", o->repeats,
            (unsigned long long)harp_state.xsave_mask, xsave_size, (unsigned long long)rflags_mask, harp_hash_hw() ? "true" : "false");
    int poll_ms = o->tick_ms > 100 ? 100 : o->tick_ms;
    if (o->max_seconds > 0 && poll_ms > 10) poll_ms = 10;
    fprintf(out, "\"tick_ms\": %d, \"test_cpu_budget_ms\": %llu, \"watchdog_poll_ms\": %d, \"worker_wait_seconds\": %.9g, ",
            o->tick_ms, 2ull * (unsigned long long)o->tick_ms, poll_ms, o->worker_wait_seconds);
}

static char automatic_report[96];

FILE *out_open(const struct options *o) {
    if (o->json_file && !strcmp(o->json_file, "-")) return stdout;
    if (!o->json_file && !o->json) return stdout;
    if (!o->json_file) {
        time_t now = time(NULL);
        struct tm stamp;
        char when[32];
        if (now == (time_t)-1 || !localtime_r(&now, &stamp) || !strftime(when, sizeof when, "%Y%m%d-%H%M%S", &stamp))
            die("cannot determine the report timestamp");
        snprintf(automatic_report, sizeof automatic_report, "./harprun-%s-XXXXXX.json", when);
        int fd = mkstemps(automatic_report, 5);   /* unique in the working directory; never overwrite a previous run */
        if (fd < 0) die("cannot create report in the current directory: %s", strerror(errno));
        FILE *f = fdopen(fd, "w");
        if (!f) {
            int saved = errno;
            close(fd); unlink(automatic_report);
            die("cannot open report: %s", strerror(saved));
        }
        return f;
    }
    FILE *f = fopen(o->json_file, "w");
    if (!f) { fprintf(stderr, "harprun: cannot write %s: %s\n", o->json_file, strerror(errno)); exit(EXIT_INTERNAL); }
    return f;
}

void out_close(FILE *f) {
    int bad = ferror(f) | (fflush(f) != 0);
    bad |= fclose(f) != 0;      /* stdout included: an error may only surface when it is closed */
    if (bad) { fprintf(stderr, "harprun: the report could not be written: %s\n", strerror(errno ? errno : EIO)); exit(EXIT_INTERNAL); }
}

FILE *summary_output(FILE *report, const struct options *o) {
    if (report == stdout && !o->json) return report;
    int on_stdout = report == stdout;
    out_close(report);   /* do not announce success unless the detailed report was written */
    return on_stdout ? stderr : stdout;
}

void summary_status(FILE *out, const struct options *o, const char *status, int partial, uint64_t elapsed_ns) {
    const char *message = !strcmp(status, "passed") ? (o->cpus ? "PASS: All voting groups agreed" : "PASS: All reference signatures matched") :
                          !strcmp(status, "observed") ? "OBSERVED: Tests completed; signatures recorded" :
                          !strcmp(status, "mismatch") ? "FINDINGS: Results differed" : "PARTIAL: Evidence is incomplete";
    fprintf(out, "\n%s (%.2f s).\n", message, elapsed_ns / 1e9);
    if (partial && !strcmp(status, "mismatch")) fputs("The run is also incomplete.\n", out);
}

void summary_saved(FILE *out, const struct options *o) {
    const char *path = o->json_file ? o->json_file : automatic_report;
    if (*path && strcmp(path, "-")) fprintf(out, "Report saved to %s\n", path);
}

static const char *outcome_name(const struct result *r) {
    if (r->exit_kind == 2) return "timeout";
    if (r->exit_kind == 1) return "signal";
    return "ok";
}

static void dump_state(FILE *f, const struct pack *p, uint32_t index) {
    static const char *names[16] = {"rax","rbx","rcx","rdx","rsi","rdi","rbp","rsp","r8","r9","r10","r11","r12","r13","r14","r15"};
    const struct harp_capture *c = &harp_state.cap;
    fprintf(f, "test %s\n", test_id(p, index));
    for (int i = 0; i < 16; i++) fprintf(f, "  %-4s %016llx\n", names[i], (unsigned long long)c->gpr[i]);
    fprintf(f, "  rflags %016llx (masked %03llx)\n", (unsigned long long)c->rflags, (unsigned long long)(c->rflags & rflags_mask));
    for (int i = 0; i < 16; i++) {
        const uint8_t *x = harp_xsave_area + 160 + 16 * i;
        uint64_t lo, hi; memcpy(&lo, x, 8); memcpy(&hi, x + 8, 8);
        /* Low qword first. */
        fprintf(f, "  xmm%-2d %016llx%016llx\n", i, (unsigned long long)lo, (unsigned long long)hi);
    }
    uint32_t mxcsr; memcpy(&mxcsr, harp_xsave_area + 24, 4);
    fprintf(f, "  mxcsr %08x  exit_kind %u signum %u code %d addr %016llx rip %016llx\n", mxcsr, c->exit_kind,
            c->signum, c->sig_code, (unsigned long long)c->sig_addr, (unsigned long long)c->rip);
}

/* ---- main: single-core mode ------------------------------------------------ */

int main(int argc, char **argv) {
    struct options o;
    parse_args(argc, argv, &o);
    if (!o.cpus && o.cpu < 0) o.cpu = sched_getcpu();   /* a single-core run never migrates: it stays where it starts */
    if (o.cpu >= 0) {
        cpu_set_t set; CPU_ZERO(&set); CPU_SET(o.cpu, &set);
        if (sched_setaffinity(0, sizeof set, &set) != 0) die_usage("--cpu: CPU %d is not available to this process (%s)", o.cpu, strerror(errno));
    }
    rflags_mask = o.flags_mask;
    detect_cpu();
    struct pack p;
    load_pack(o.pack_path, &p);
    uint32_t n_sel;
    uint32_t *sel = select_tests(&o, &p, &n_sel);
    int dump_index = -1;
    if (o.dump_id) {
        for (uint32_t k = 0; k < n_sel; k++) if (!strcmp(o.dump_id, test_id(&p, sel[k]))) dump_index = (int)sel[k];
        if (dump_index < 0) die_usage("--dump: '%s' is not among the selected tests", o.dump_id);
    }
    map_regions(&p);
    build_images(&p);
    if (o.check) {      /* everything the loader dereferences has been read; nothing is executed */
        printf("pack ok: %u tests, %llu data images, %u selected\n", p.h->n_tests, (unsigned long long)p.h->n_images, n_sel);
        out_close(stdout);
        return EXIT_OK;
    }
    install_signals();
    if (o.cpus) return orchestrate(&o, &p, sel, n_sel);
    struct result *res = calloc(n_sel, sizeof *res);
    if (!res) die("calloc");
    uint64_t start = now_ns();
    uint64_t deadline = o.max_seconds > 0 ? start + (uint64_t)(o.max_seconds * 1e9) : 0;
    start_watchdog(o.tick_ms, deadline);
    int interrupted = 0;
    uint32_t done = 0, started = 0;
    for (uint32_t k = 0; k < n_sel && !interrupted; k++) {
        struct result *r = &res[k];
        interrupted = harp_cycle(&o, &p, sel[k], r, NULL, deadline);
        if (!r->runs) break;
        started++;                           /* retain evidence even when the repeats were interrupted */
        if (!interrupted && (int)sel[k] == dump_index) { /* show the state of a fresh execution of that test */
            struct result tmp; uint64_t cyc;
            run_once(&p, sel[k], &tmp, &cyc);
            if (!execution_cancelled) dump_state(stderr, &p, sel[k]);
            if (execution_cancelled || (deadline && now_ns() >= deadline)) interrupted = 1;
        }
        if (r->runs > r->timeouts && p.tests[sel[k]].expected_sig) { r->checked = 1; r->match = (r->sig == p.tests[sel[k]].expected_sig); }
        if (r->runs == (uint32_t)o.repeats) done++;
    }
    uint64_t end = now_ns();
    /* Even the final execution's host-side capture/hash or dump can cross the budget. */
    if (deadline && end >= deadline) interrupted = 1;
    uint64_t elapsed = end - start;

    uint32_t n_ok = 0, n_signal = 0, n_timeout = 0, n_unstable = 0, n_checked = 0, n_mismatch = 0, n_unexpected = 0;
    uint64_t total_runs = 0, total_timeouts = 0, total_ns = 0, total_cycle = 0;
    int legacy_capture = 0;
    for (uint32_t k = 0; k < started; k++) {
        const struct result *r = &res[k];
        if (r->exit_kind == 0) n_ok++; else if (r->exit_kind == 1) n_signal++;
        if (r->timeouts) n_timeout++;
        total_timeouts += r->timeouts;
        if (r->unstable) n_unstable++;
        if (r->exit_kind == 1 && !r->vec_full) legacy_capture = 1;
        if (r->checked) { n_checked++; if (!r->match) n_mismatch++; }
        if (r->exit_kind == 1 && !(r->checked && r->match)) n_unexpected++;   /* a fault is clean only if a reference says so */
        total_runs += r->runs; total_ns += r->ns_sum; total_cycle += r->cycle_sum;
    }
    /* Findings win; then anything that leaves the evidence incomplete; a clean run is "passed" only
     * if every test was checked against a reference, otherwise it is an observation. */
    int findings = n_unstable || n_mismatch;
    int partial = interrupted || n_timeout || n_unexpected || legacy_capture;
    const char *status = findings ? "mismatch" : partial ? "partial" : (n_checked == done && done) ? "passed" : "observed";

    FILE *out = out_open(&o);
    if (o.json) {
        report_header(out, &o, &p, "single");
        fprintf(out, "\"cpu\": %d, \"status\": \"%s\", \"partial\": %s, \"tests_selected\": %u, \"tests_done\": %u, \"tests_started\": %u, \"duration_ms\": %llu, ",
                o.cpu, status, partial ? "true" : "false", n_sel, done, started, (unsigned long long)(elapsed / 1000000ull));
        fprintf(out, "\"ns_per_run\": %llu, \"ns_per_cycle\": %llu, ", (unsigned long long)(total_runs ? total_ns / total_runs : 0),
                (unsigned long long)(total_runs ? total_cycle / total_runs : 0));
        fprintf(out, "\"summary\": {\"ok\": %u, \"signal\": %u, \"timeout\": %u, \"timeouts\": %llu, \"comparable_runs\": %llu, \"unexpected_signals\": %u, \"unstable\": %u, \"checked\": %u, \"mismatch\": %u}, ",
                n_ok, n_signal, n_timeout, (unsigned long long)total_timeouts, (unsigned long long)(total_runs - total_timeouts),
                n_unexpected, n_unstable, n_checked, n_mismatch);
        fprintf(out, "\"tests\": [");
        int first = 1;
        for (uint32_t k = 0; k < started; k++) {
            const struct result *r = &res[k];
            if (o.brief && r->runs == (uint32_t)o.repeats && r->exit_kind == 0 && !r->timeouts && !r->unstable && (!r->checked || r->match)) continue;
            fprintf(out, "%s{\"id\": ", first ? "" : ", "); first = 0;
            json_escape(out, test_id(&p, sel[k]));
            fprintf(out, ", \"signature\": \"%016llx\", \"components\": {\"gpr\": \"%016llx\", \"flags\": \"%016llx\", \"vec\": \"%016llx\", \"mem\": \"%016llx\", \"stack\": \"%016llx\", \"exit\": \"%016llx\"}",
                    (unsigned long long)r->sig, (unsigned long long)r->comp[0], (unsigned long long)r->comp[1], (unsigned long long)r->comp[2],
                    (unsigned long long)r->comp[3], (unsigned long long)r->comp[4], (unsigned long long)r->comp[5]);
            fprintf(out, ", \"outcome\": \"%s\", \"runs\": %u, \"unstable\": %u, \"ns_min\": %llu, \"ns_max\": %llu, \"ns_cycle\": %llu",
                    outcome_name(r), r->runs, r->unstable, (unsigned long long)r->ns_min, (unsigned long long)r->ns_max,
                    (unsigned long long)(r->cycle_sum / r->runs));
            fprintf(out, ", \"comparable_runs\": %u, \"timeouts\": %u", r->runs - r->timeouts, r->timeouts);
            if (r->timeouts)
                fprintf(out, ", \"first_timeout_repeat\": %u, \"timeout_cpu_ns\": %llu, \"timeout_wall_ns\": %llu",
                        r->first_timeout_repeat, (unsigned long long)r->timeout_cpu_ns, (unsigned long long)r->timeout_wall_ns);
            else fputs(", \"first_timeout_repeat\": null, \"timeout_cpu_ns\": null, \"timeout_wall_ns\": null", out);
            fprintf(out, ", \"complete\": %s", r->runs == (uint32_t)o.repeats ? "true" : "false");
            if (r->exit_kind)
                fprintf(out, ", \"signal\": {\"signum\": %u, \"code\": %d, \"addr\": \"%llx\", \"rip_offset\": %lld, \"vector_capture\": \"%s\"}",
                        r->signum, r->sig_code, (unsigned long long)r->sig_addr, r->rip_off == UINT64_MAX ? -1LL : (long long)r->rip_off,
                        r->exit_kind == 2 ? "none" : r->vec_full ? "full" : "legacy");
            if (r->checked) fprintf(out, ", \"expected\": \"%016llx\", \"match\": %s", (unsigned long long)p.tests[sel[k]].expected_sig, r->match ? "true" : "false");
            else fprintf(out, ", \"expected\": null, \"match\": null");
            fputc('}', out);
        }
        fprintf(out, "]}\n");
    } else {
        for (uint32_t k = 0; k < started; k++) {
            const struct result *r = &res[k];
            if (o.brief && r->runs == (uint32_t)o.repeats && r->exit_kind == 0 && !r->timeouts && !r->unstable && (!r->checked || r->match)) continue;
            fprintf(out, "%s %016llx %s runs=%u comparable_runs=%u timeouts=%u unstable=%u ns=%llu%s%s%s", test_id(&p, sel[k]), (unsigned long long)r->sig,
                    outcome_name(r), r->runs, r->runs - r->timeouts, r->timeouts, r->unstable, (unsigned long long)(r->ns_sum / r->runs),
                    r->checked ? (r->match ? " match" : " MISMATCH") : "", r->exit_kind == 1 && !r->vec_full ? " vector-capture=legacy" : "",
                    r->runs == (uint32_t)o.repeats ? "" : " incomplete");
            if (r->timeouts) fprintf(out, " first_timeout_repeat=%u timeout_cpu_ns=%llu timeout_wall_ns=%llu", r->first_timeout_repeat,
                                     (unsigned long long)r->timeout_cpu_ns, (unsigned long long)r->timeout_wall_ns);
            fputc('\n', out);
        }
        fprintf(out, "status=%s done=%u/%u ok=%u signal=%u timeout=%u timeouts=%llu unstable=%u checked=%u mismatch=%u ns_per_run=%llu ns_per_cycle=%llu\n", status, done, n_sel,
                n_ok, n_signal, n_timeout, (unsigned long long)total_timeouts, n_unstable, n_checked, n_mismatch,
                (unsigned long long)(total_runs ? total_ns / total_runs : 0), (unsigned long long)(total_runs ? total_cycle / total_runs : 0));
    }
    out = summary_output(out, &o);
    summary_status(out, &o, status, partial, elapsed);
    fprintf(out, "%u/%u %s completed on CPU %d; %llu %s (%d %s requested per test).\n",
            done, n_sel, n_sel == 1 ? "test" : "tests", o.cpu, (unsigned long long)total_runs,
            total_runs == 1 ? "execution" : "executions", o.repeats, o.repeats == 1 ? "execution" : "executions");
    if (findings) {
        fprintf(out, "Findings: %u unstable tests, %u reference mismatches.\n", n_unstable, n_mismatch);
        uint32_t shown = 0;
        for (uint32_t k = 0; k < started && shown < 3; k++) {
            const struct result *r = &res[k];
            if (!r->unstable && (!r->checked || r->match)) continue;
            fprintf(out, "  CPU %d, %s: %s%s%s\n", o.cpu, test_id(&p, sel[k]), r->unstable ? "unstable" : "",
                    r->unstable && r->checked && !r->match ? ", " : "", r->checked && !r->match ? "reference mismatch" : "");
            shown++;
        }
        if (n_unstable + n_mismatch > shown) fputs("  See the detailed report for all findings.\n", out);
    } else if (!partial) {
        fputs(n_checked == done ? "No instability or reference mismatches detected.\n" : "No instability detected; unreferenced signatures are observations.\n", out);
    }
    if (partial) {
        fputs("Incomplete:", out);
        if (interrupted) fputs(" time budget reached;", out);
        if (n_timeout) fprintf(out, " %llu timeout executions across %u tests;", (unsigned long long)total_timeouts, n_timeout);
        if (n_unexpected) fprintf(out, " %u unexpected signals;", n_unexpected);
        if (legacy_capture) fputs(" incomplete vector capture;", out);
        if (started > done) fprintf(out, " %u interrupted repeat set;", started - done);
        fputc('\n', out);
    }
    if (total_timeouts) {
        uint32_t shown = 0;
        for (uint32_t k = 0; k < started && shown < 3; k++) {
            const struct result *r = &res[k];
            if (!r->timeouts) continue;
            fprintf(out, "  CPU %d, %s, repeat index %u: timeout (CPU %.3f ms, wall %.3f ms).\n",
                    o.cpu, test_id(&p, sel[k]), r->first_timeout_repeat, r->timeout_cpu_ns / 1e6, r->timeout_wall_ns / 1e6);
            shown++;
        }
        if (n_timeout > shown) fputs("  See the detailed report for remaining timeout diagnostics.\n", out);
    }
    summary_saved(out, &o);
    out_close(out);
    return findings ? EXIT_MISMATCH : partial ? EXIT_PARTIAL : EXIT_OK;
}
