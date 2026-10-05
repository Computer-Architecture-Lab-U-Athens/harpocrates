/* Voting mode: one pinned worker per CPU, grouped by core design. Each group runs one round at a
 * time: its workers execute every selected test, publish their cells and wait; the parent votes
 * the round and only then releases the group's next one. There is one table generation per
 * worker. A worker that fails ends the run: every published observation is kept, including evidence
 * in an unfinished round. */
#define _GNU_SOURCE
#include "harprun.h"

#include <errno.h>
#include <sched.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "hash.h"

#define IDLE UINT64_MAX
#define MAX_FINDINGS 100000u
#define TABLE_LIMIT (4ull << 30)
#define PENDING_BYTES (64ull << 20)     /* per group: majority vectors waiting for the other groups */

#define LOAD(p) __atomic_load_n((p), __ATOMIC_ACQUIRE)
#define STORE(p, v) __atomic_store_n((p), (v), __ATOMIC_RELEASE)

struct cell {
    uint64_t sig; uint16_t comp[6]; uint8_t exit_kind, unstable, vec_legacy, incomplete;
    uint32_t signum, runs, timeouts, first_timeout_repeat;
    uint64_t timeout_cpu_ns, timeout_wall_ns;
};

struct slot {
    uint64_t release;       /* parent: rounds this worker may start (round r runs when release > r) */
    uint64_t ready;         /* worker: pinned and announced */
    uint64_t core_type;
    uint64_t ack;           /* worker: rounds started; it writes cells of round r only after ack = r + 1 */
    uint64_t done;          /* worker: rounds completed and published */
    uint64_t cells_done;    /* worker: cells published in the round it is in */
    uint64_t heartbeat;     /* worker: bumped before every execution */
    uint64_t current;       /* worker: index of the test it is executing, or IDLE */
    uint64_t finished;      /* worker: left its loop on its own */
    uint64_t ns_sum, cycles;
    uint64_t pad[5];
};

struct shared { uint64_t stop, deadline; };

struct worker { int cpu, group; pid_t pid; int alive, failed, cancelled; char why[96]; uint64_t fail_round, fail_cells, fail_current;
                uint64_t last_beat, last_change_ns, released_ns, timeouts; uint32_t minorities, unstable; };

enum { F_MINORITY, F_TIE, F_UNSTABLE, F_REFERENCE };
struct finding { uint32_t kind, cpu, group, round, test; uint64_t maj, got; uint8_t comps; };
struct timeout_event {
    uint32_t cpu, group, round, test, count, first_repeat;
    uint64_t cpu_ns, wall_ns;
};

struct group { uint64_t type; uint32_t size, next_round, pend_head, pend_n; uint64_t *pend; uint32_t *pend_round; };

static struct {
    const struct options *o; const struct pack *p; const uint32_t *sel;
    uint32_t n, n_sel, n_groups, pend_cap, cmp_round, cross_skipped;
    struct shared *sh; struct slot *slots; struct cell *cells;
    struct worker *w; struct group *g;
    struct finding *findings; uint32_t n_findings, dropped_findings;
    struct timeout_event *timeout_events; uint32_t n_timeout_events, dropped_timeouts;
    uint32_t minorities, ties, unstable, references, ungraded_cells, incomplete_cycles;
    uint64_t timeouts;
    uint8_t *cross_diff;        /* [n_sel] */
    uint8_t *agreed_fault;      /* [n_groups][n_sel]: 1 signal, 2 timeout */
    uint32_t *agreed_signum;
    uint8_t *capture_issues;    /* [n_groups][n_sel]: legacy-only faults; summary counts unique group/test pairs */
    int budget_expired, failures;
} V;

static struct cell *cell_at(uint32_t wi, uint32_t k) { return V.cells + (size_t)wi * V.n_sel + k; }

/* ---- worker ------------------------------------------------------------------ */

static void worker(uint32_t wi, pid_t parent) {
    const struct options *o = V.o;
    struct slot *s = &V.slots[wi];
    int cpu = V.w[wi].cpu;
    prctl(PR_SET_PDEATHSIG, SIGKILL);       /* never outlive the parent */
    if (getppid() != parent) _exit(0);
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    if (sched_setaffinity(0, sizeof set, &set) != 0) _exit(3);
    s->core_type = harp_core_type();
    harp_heartbeat = &s->heartbeat;
    start_watchdog(o->tick_ms, V.sh->deadline);
    STORE(&s->ready, 1);
    for (uint64_t round = 0; round < (uint64_t)o->rounds; round++) {
        STORE(&s->current, IDLE);
        while (LOAD(&s->release) <= round) {                /* the barrier: the parent has not voted the previous round yet */
            if (LOAD(&V.sh->stop)) goto out;
            struct timespec ts = {0, 50000};
            nanosleep(&ts, NULL);
        }
        STORE(&s->cells_done, 0);
        STORE(&s->ack, round + 1);
        for (uint32_t k = 0; k < V.n_sel; k++) {
            if (LOAD(&V.sh->stop)) goto out;
            STORE(&s->current, k);
            struct result r;
            int interrupted = harp_cycle(o, V.p, V.sel[k], &r, &V.sh->stop, V.sh->deadline);
            if (!r.runs) goto out;
            struct cell c = {.sig = r.sig, .exit_kind = (uint8_t)r.exit_kind, .unstable = r.unstable != 0,
                             .vec_legacy = r.exit_kind == 1 && !r.vec_full, .incomplete = interrupted != 0,
                             .signum = r.signum, .runs = r.runs, .timeouts = r.timeouts,
                             .first_timeout_repeat = r.first_timeout_repeat,
                             .timeout_cpu_ns = r.timeout_cpu_ns, .timeout_wall_ns = r.timeout_wall_ns};
            for (int j = 0; j < 6; j++) c.comp[j] = (uint16_t)(r.comp[j] ^ (r.comp[j] >> 16) ^ (r.comp[j] >> 32) ^ (r.comp[j] >> 48));
            *cell_at(wi, k) = c;
            if (!interrupted) { s->ns_sum += r.cycle_sum; s->cycles++; }
            STORE(&s->cells_done, k + 1);
            if (interrupted) goto out;
        }
        STORE(&s->done, round + 1);
    }
out:
    STORE(&s->current, IDLE);
    STORE(&s->finished, 1);
    _exit(0);
}

/* ---- parent: voting ---------------------------------------------------------- */

static void add_finding(struct finding f) {
    if (V.n_findings >= MAX_FINDINGS) { V.dropped_findings++; return; }
    V.findings[V.n_findings++] = f;
}

static uint8_t comp_diff(const struct cell *a, const struct cell *b) {
    uint8_t m = 0;
    for (int j = 0; j < 6; j++) if (a->comp[j] != b->comp[j]) m |= (uint8_t)(1u << j);
    return m;
}

/* Compare the groups' values of the rounds that every group has voted. */
static void compare_groups(void) {
    if (V.n_groups < 2) return;
    for (;;) {
        for (uint32_t g = 0; g < V.n_groups; g++) if (V.g[g].next_round <= V.cmp_round) return;
        int complete = 1;
        for (uint32_t g = 0; g < V.n_groups; g++) if (!V.g[g].pend_n || V.g[g].pend_round[V.g[g].pend_head] != V.cmp_round) complete = 0;
        if (complete) {
            for (uint32_t k = 0; k < V.n_sel; k++) {
                uint64_t first = 0;
                for (uint32_t g = 0; g < V.n_groups; g++) {
                    uint64_t v = V.g[g].pend[(size_t)V.g[g].pend_head * V.n_sel + k];
                    if (!v) continue;                       /* that group had no value for the test (a tie) */
                    if (!first) first = v; else if (v != first) V.cross_diff[k] = 1;
                }
            }
        } else V.cross_skipped++;
        for (uint32_t g = 0; g < V.n_groups; g++) {
            struct group *G = &V.g[g];
            if (G->pend_n && G->pend_round[G->pend_head] == V.cmp_round) { G->pend_head = (G->pend_head + 1) % V.pend_cap; G->pend_n--; }
        }
        V.cmp_round++;
    }
}

/* Grade observations in one test column. The configured membership is the quorum even if
 * some workers did not publish. Each column is visited once: in a complete round's vote or,
 * after every worker has stopped, when retaining an unfinished round's evidence. */
static uint64_t vote_test(uint32_t g, uint32_t round, uint32_t k, const uint32_t *members, uint32_t nm) {
    if (!nm) return 0;
    struct group *G = &V.g[g];
    const struct hpk_test *t = &V.p->tests[V.sel[k]];
    uint32_t comparable[1024], nc = 0;
    for (uint32_t i = 0; i < nm; i++) {
        uint32_t wi = members[i];
        const struct cell *c = cell_at(wi, k);
        V.incomplete_cycles += c->incomplete;
        V.timeouts += c->timeouts;
        V.w[wi].timeouts += c->timeouts;
        if (c->timeouts) {
            if (V.n_timeout_events == MAX_FINDINGS) V.dropped_timeouts++;
            else V.timeout_events[V.n_timeout_events++] = (struct timeout_event){
                (uint32_t)V.w[wi].cpu, g, round, k, c->timeouts, c->first_timeout_repeat,
                c->timeout_cpu_ns, c->timeout_wall_ns};
        }
        if (c->runs <= c->timeouts) continue;       /* a watchdog interruption is not a result to compare */
        comparable[nc++] = wi;
        if (c->vec_legacy) V.capture_issues[(size_t)g * V.n_sel + k] = 1;
        if (!c->unstable) continue;
        V.unstable++; V.w[wi].unstable++;
        add_finding((struct finding){F_UNSTABLE, (uint32_t)V.w[wi].cpu, g, round, k, 0, c->sig, 0});
    }
    if (!nc) {
        if (nm == G->size) {
            V.agreed_fault[(size_t)g * V.n_sel + k] = 2;
            V.agreed_signum[(size_t)g * V.n_sel + k] = SIGALRM;
        }
        return 0;
    }
    const struct cell *ref = cell_at(comparable[0], k);
    uint32_t best = 0;
    for (uint32_t i = 0; i < nc; i++) {
        uint32_t cnt = 0;
        for (uint32_t j = 0; j < nc; j++) if (cell_at(comparable[j], k)->sig == cell_at(comparable[i], k)->sig) cnt++;
        if (cnt > best) { best = cnt; ref = cell_at(comparable[i], k); }
    }
    if (G->size == 1) { V.ungraded_cells++; return ref->sig; }
    if (best * 2 <= G->size) {
        /* Missing or timed-out evidence does not shrink the quorum and alone is not a tie.
         * Only differing completed results can establish an actual disagreement. */
        const struct cell *first = cell_at(comparable[0], k);
        for (uint32_t i = 1; i < nc; i++) {
            const struct cell *other = cell_at(comparable[i], k);
            if (other->sig == first->sig) continue;
            V.ties++;
            add_finding((struct finding){F_TIE, 0, g, round, k, first->sig, other->sig, comp_diff(first, other)});
            break;
        }
        return 0;
    }
    for (uint32_t i = 0; i < nc; i++) {
        const struct cell *c = cell_at(comparable[i], k);
        if (c->sig == ref->sig) continue;
        V.minorities++; V.w[comparable[i]].minorities++;
        add_finding((struct finding){F_MINORITY, (uint32_t)V.w[comparable[i]].cpu, g, round, k, ref->sig, c->sig, comp_diff(c, ref)});
    }
    if (t->expected_sig && t->expected_sig != ref->sig) {
        V.references++;
        add_finding((struct finding){F_REFERENCE, 0, g, round, k, t->expected_sig, ref->sig, 0});
    }
    if (ref->exit_kind == 1 && (!t->expected_sig || t->expected_sig != ref->sig)) {
        V.agreed_fault[(size_t)g * V.n_sel + k] = ref->exit_kind;
        V.agreed_signum[(size_t)g * V.n_sel + k] = ref->signum;
    }
    return ref->sig;
}

/* Every configured member of group g has published the complete round `round`. */
static void vote(uint32_t g, uint32_t round) {
    struct group *G = &V.g[g];
    uint32_t members[1024], nm = 0;
    for (uint32_t wi = 0; wi < V.n; wi++) if (V.w[wi].group == (int)g) members[nm++] = wi;
    if (G->pend_n == V.pend_cap) { G->pend_head = (G->pend_head + 1) % V.pend_cap; G->pend_n--; }
    uint32_t slot = (G->pend_head + G->pend_n) % V.pend_cap;
    G->pend_round[slot] = round; G->pend_n++;
    uint64_t *value = G->pend + (size_t)slot * V.n_sel;
    for (uint32_t k = 0; k < V.n_sel; k++) value[k] = vote_test(g, round, k, members, nm);
    G->next_round = round + 1;
    compare_groups();
}

/* Only reaped workers have immutable generations when inspecting published prefixes.
 * Do not advance rounds_voted or cross-group history for incomplete rounds/repeat cycles. */
static void retain_partial_round(uint32_t g, uint32_t round) {
    for (uint32_t k = 0; k < V.n_sel; k++) {
        uint32_t members[1024], nm = 0;
        for (uint32_t wi = 0; wi < V.n; wi++) {
            const struct slot *s = &V.slots[wi];
            if (!V.w[wi].alive && V.w[wi].group == (int)g && LOAD(&s->ack) == (uint64_t)round + 1 && LOAD(&s->cells_done) > k)
                members[nm++] = wi;
        }
        vote_test(g, round, k, members, nm);
    }
}

static int round_published(uint32_t g, uint32_t round) {
    for (uint32_t wi = 0; wi < V.n; wi++)
        if (V.w[wi].group == (int)g && LOAD(&V.slots[wi].done) < (uint64_t)round + 1) return 0;
    return 1;
}

static void fail(uint32_t wi, const char *why) {
    struct worker *w = &V.w[wi];
    if (w->failed) return;
    w->failed = 1; V.failures++;
    snprintf(w->why, sizeof w->why, "%s", why);
    w->fail_round = LOAD(&V.slots[wi].ack) ? LOAD(&V.slots[wi].ack) - 1 : 0;
    w->fail_cells = LOAD(&V.slots[wi].cells_done);
    w->fail_current = LOAD(&V.slots[wi].current);
}

static void reap(void) {
    int status;
    pid_t pid;
    while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
        for (uint32_t wi = 0; wi < V.n; wi++) {
            struct worker *w = &V.w[wi];
            if (w->pid != pid || !w->alive) continue;
            w->alive = 0;
            if (LOAD(&V.slots[wi].finished)) continue;
            if (w->cancelled && WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL) continue;
            char why[96];
            if (WIFSIGNALED(status)) snprintf(why, sizeof why, "worker killed by signal %d", WTERMSIG(status));
            else snprintf(why, sizeof why, "worker exited with status %d", WEXITSTATUS(status));
            fail(wi, why);
        }
    }
}

/* ---- report ------------------------------------------------------------------ */

static const char *comp_names[6] = {"gpr", "flags", "vec", "mem", "stack", "exit"};
static const char *kind_names[4] = {"minority", "tie", "unstable", "reference"};

static void print_comps(FILE *out, uint8_t comps, const char *sep, const char *quote) {
    int first = 1;
    for (int j = 0; j < 6; j++) if (comps & (1u << j)) { fprintf(out, "%s%s%s%s", first ? "" : sep, quote, comp_names[j], quote); first = 0; }
}

static const char *worker_state(uint32_t wi) {
    return V.w[wi].failed ? "failed" : LOAD(&V.slots[wi].done) >= (uint64_t)V.o->rounds ? "done" : "stopped";
}

static void report(FILE *out, const char *status, int partial, uint64_t elapsed, uint32_t cross, uint32_t agreed_signals, uint32_t agreed_timeouts, uint32_t ungraded_groups, uint32_t legacy_captures) {
    const struct options *o = V.o;
    uint64_t cells = 0;
    for (uint32_t wi = 0; wi < V.n; wi++) cells += V.slots[wi].cycles;
    if (o->json) {
        report_header(out, o, V.p, "vote");
        fprintf(out, "\"orchestration\": \"simple\", \"rounds\": %d, \"tests_selected\": %u, \"status\": \"%s\", \"partial\": %s, \"duration_ms\": %llu, ",
                o->rounds, V.n_sel, status, partial ? "true" : "false", (unsigned long long)(elapsed / 1000000ull));
        fprintf(out, "\"summary\": {\"cells\": %llu, \"minorities\": %u, \"ties\": %u, \"unstable\": %u, \"reference_mismatches\": %u, \"agreed_signals\": %u, "
                     "\"agreed_timeouts\": %u, \"cross_group_tests\": %u, \"cross_group_rounds_skipped\": %u, \"worker_failures\": %d, \"ungraded_groups\": %u, "
                     "\"budget_expired\": %s, \"dropped_findings\": %u, \"timeouts\": %llu, \"dropped_timeouts\": %u, \"incomplete_cycles\": %u, \"legacy_vector_captures\": %u}, ",
                (unsigned long long)cells, V.minorities, V.ties, V.unstable, V.references, agreed_signals, agreed_timeouts, cross, V.cross_skipped,
                V.failures, ungraded_groups, V.budget_expired ? "true" : "false", V.dropped_findings, (unsigned long long)V.timeouts, V.dropped_timeouts, V.incomplete_cycles, legacy_captures);
        fprintf(out, "\"groups\": [");
        for (uint32_t g = 0; g < V.n_groups; g++) {
            fprintf(out, "%s{\"id\": %u, \"core_type\": \"%s\", \"voters\": %u, \"graded\": %s, \"rounds_voted\": %u, \"cpus\": [", g ? ", " : "", g,
                    harp_core_type_name(V.g[g].type), V.g[g].size, V.g[g].size >= 2 ? "true" : "false", V.g[g].next_round);
            int first = 1;
            for (uint32_t wi = 0; wi < V.n; wi++) if (V.w[wi].group == (int)g) { fprintf(out, "%s%d", first ? "" : ", ", V.w[wi].cpu); first = 0; }
            fprintf(out, "]}");
        }
        fprintf(out, "], \"cores\": [");
        int first = 1;
        for (uint32_t wi = 0; wi < V.n; wi++) {
            const struct worker *w = &V.w[wi];
            const struct slot *s = &V.slots[wi];
            if (o->brief && !w->failed && !w->minorities && !w->unstable && !w->timeouts && LOAD(&s->done) >= (uint64_t)o->rounds) continue;
            fprintf(out, "%s{\"cpu\": %d, \"group\": %d, \"core_type\": \"%s\", \"state\": \"%s\", \"rounds_completed\": %llu, \"cells\": %llu, \"ns_per_cycle\": %llu, "
                         "\"minorities\": %u, \"unstable\": %u, \"timeouts\": %llu", first ? "" : ", ", w->cpu, w->group, harp_core_type_name(V.g[w->group].type), worker_state(wi),
                    (unsigned long long)LOAD(&s->done), (unsigned long long)s->cycles, (unsigned long long)(s->cycles ? s->ns_sum / s->cycles : 0), w->minorities, w->unstable, (unsigned long long)w->timeouts);
            if (w->failed) { fprintf(out, ", \"failure\": "); json_escape(out, w->why); }
            fputc('}', out); first = 0;
        }
        fprintf(out, "], \"findings\": [");
        for (uint32_t i = 0; i < V.n_findings; i++) {
            const struct finding *f = &V.findings[i];
            fprintf(out, "%s{\"kind\": \"%s\", \"group\": %u, \"round\": %u, \"test\": ", i ? ", " : "", kind_names[f->kind], f->group, f->round);
            json_escape(out, test_id(V.p, V.sel[f->test]));
            if (f->kind == F_MINORITY) { fprintf(out, ", \"cpu\": %u, \"majority\": \"%016llx\", \"minority\": \"%016llx\", \"components\": [", f->cpu, (unsigned long long)f->maj, (unsigned long long)f->got); print_comps(out, f->comps, ", ", "\""); fputc(']', out); }
            else if (f->kind == F_TIE) { fprintf(out, ", \"signatures\": [\"%016llx\", \"%016llx\"], \"components\": [", (unsigned long long)f->maj, (unsigned long long)f->got); print_comps(out, f->comps, ", ", "\""); fputc(']', out); }
            else if (f->kind == F_UNSTABLE) fprintf(out, ", \"cpu\": %u, \"signature\": \"%016llx\"", f->cpu, (unsigned long long)f->got);
            else fprintf(out, ", \"expected\": \"%016llx\", \"agreed\": \"%016llx\"", (unsigned long long)f->maj, (unsigned long long)f->got);
            fputc('}', out);
        }
        fprintf(out, "], \"timeouts\": [");
        for (uint32_t i = 0; i < V.n_timeout_events; i++) {
            const struct timeout_event *t = &V.timeout_events[i];
            fprintf(out, "%s{\"cpu\": %u, \"group\": %u, \"round\": %u, \"test\": ", i ? ", " : "", t->cpu, t->group, t->round);
            json_escape(out, test_id(V.p, V.sel[t->test]));
            fprintf(out, ", \"count\": %u, \"first_repeat\": %u, \"cpu_ns\": %llu, \"wall_ns\": %llu, \"reason\": \"cpu_budget\"}",
                    t->count, t->first_repeat, (unsigned long long)t->cpu_ns, (unsigned long long)t->wall_ns);
        }
        fprintf(out, "], \"agreed_faults\": [");
        first = 1;
        for (uint32_t g = 0; g < V.n_groups; g++) for (uint32_t k = 0; k < V.n_sel; k++) {
            uint8_t a = V.agreed_fault[(size_t)g * V.n_sel + k];
            if (!a) continue;
            fprintf(out, "%s{\"group\": %u, \"test\": ", first ? "" : ", ", g); json_escape(out, test_id(V.p, V.sel[k]));
            fprintf(out, ", \"outcome\": \"%s\", \"signum\": %u}", a == 2 ? "timeout" : "signal", V.agreed_signum[(size_t)g * V.n_sel + k]); first = 0;
        }
        fprintf(out, "], \"capture_issues\": [");
        first = 1;
        for (uint32_t g = 0; g < V.n_groups; g++) for (uint32_t k = 0; k < V.n_sel; k++) {
            if (!V.capture_issues[(size_t)g * V.n_sel + k]) continue;
            fprintf(out, "%s{\"group\": %u, \"test\": ", first ? "" : ", ", g); json_escape(out, test_id(V.p, V.sel[k]));
            fputs(", \"vector_capture\": \"legacy\"}", out); first = 0;
        }
        fprintf(out, "], \"unfinished\": [");
        first = 1;
        for (uint32_t wi = 0; wi < V.n; wi++) {
            const struct slot *s = &V.slots[wi];
            uint64_t done = LOAD(&s->done);
            if (done >= (uint64_t)o->rounds) continue;
            uint64_t in_round = LOAD(&s->ack) > done, cd = in_round ? LOAD(&s->cells_done) : 0;
            uint32_t partial_runs = 0;
            if (!V.w[wi].alive && cd && cell_at(wi, (uint32_t)cd - 1)->incomplete) {
                cd--;
                partial_runs = cell_at(wi, (uint32_t)cd)->runs;
            }
            fprintf(out, "%s{\"cpu\": %d, \"round\": %llu, \"tests_completed\": %llu, \"next_test\": ", first ? "" : ", ", V.w[wi].cpu, (unsigned long long)done, (unsigned long long)cd);
            if (cd < V.n_sel) json_escape(out, test_id(V.p, V.sel[cd])); else fprintf(out, "null");
            if (partial_runs) fprintf(out, ", \"partial_runs\": %u", partial_runs);
            fputc('}', out); first = 0;
        }
        fprintf(out, "], \"cross_group_tests\": [");
        first = 1;
        for (uint32_t k = 0; k < V.n_sel; k++) if (V.cross_diff[k]) { fputs(first ? "" : ", ", out); json_escape(out, test_id(V.p, V.sel[k])); first = 0; }
        fprintf(out, "]}\n");
        return;
    }
    for (uint32_t g = 0; g < V.n_groups; g++)
        fprintf(out, "group %u %-7s voters=%u rounds_voted=%u/%d%s\n", g, harp_core_type_name(V.g[g].type), V.g[g].size, V.g[g].next_round, o->rounds, V.g[g].size < 2 ? " UNGRADED (single voter)" : "");
    for (uint32_t wi = 0; wi < V.n; wi++) {
        const struct worker *w = &V.w[wi];
        const struct slot *s = &V.slots[wi];
        if (o->brief && !w->failed && !w->minorities && !w->unstable && !w->timeouts && LOAD(&s->done) >= (uint64_t)o->rounds) continue;
        fprintf(out, "cpu %3d group %d %-7s rounds=%llu cells=%llu ns_cycle=%llu minorities=%u unstable=%u timeouts=%llu state=%s%s%s\n", w->cpu, w->group, harp_core_type_name(V.g[w->group].type),
                (unsigned long long)LOAD(&s->done), (unsigned long long)s->cycles, (unsigned long long)(s->cycles ? s->ns_sum / s->cycles : 0), w->minorities, w->unstable, (unsigned long long)w->timeouts,
                worker_state(wi), w->failed ? ": " : "", w->failed ? w->why : "");
    }
    for (uint32_t i = 0; i < V.n_findings; i++) {
        const struct finding *f = &V.findings[i];
        const char *id = test_id(V.p, V.sel[f->test]);
        if (f->kind == F_MINORITY) { fprintf(out, "minority cpu %u round %u %s majority %016llx got %016llx ", f->cpu, f->round, id, (unsigned long long)f->maj, (unsigned long long)f->got); print_comps(out, f->comps, " ", ""); fputc('\n', out); }
        else if (f->kind == F_TIE) fprintf(out, "tie group %u round %u %s %016llx vs %016llx\n", f->group, f->round, id, (unsigned long long)f->maj, (unsigned long long)f->got);
        else if (f->kind == F_UNSTABLE) fprintf(out, "unstable cpu %u round %u %s\n", f->cpu, f->round, id);
        else fprintf(out, "reference group %u round %u %s expected %016llx agreed %016llx\n", f->group, f->round, id, (unsigned long long)f->maj, (unsigned long long)f->got);
    }
    for (uint32_t i = 0; i < V.n_timeout_events; i++) {
        const struct timeout_event *t = &V.timeout_events[i];
        fprintf(out, "timeout cpu %u group %u round %u %s count=%u first_repeat=%u cpu_ns=%llu wall_ns=%llu reason=cpu_budget\n",
                t->cpu, t->group, t->round, test_id(V.p, V.sel[t->test]), t->count, t->first_repeat,
                (unsigned long long)t->cpu_ns, (unsigned long long)t->wall_ns);
    }
    for (uint32_t g = 0; g < V.n_groups; g++) for (uint32_t k = 0; k < V.n_sel; k++) {
        uint8_t a = V.agreed_fault[(size_t)g * V.n_sel + k];
        if (a) fprintf(out, "agreed-fault group %u %s %s %u\n", g, test_id(V.p, V.sel[k]), a == 2 ? "timeout" : "signal", V.agreed_signum[(size_t)g * V.n_sel + k]);
    }
    for (uint32_t g = 0; g < V.n_groups; g++) for (uint32_t k = 0; k < V.n_sel; k++)
        if (V.capture_issues[(size_t)g * V.n_sel + k])
            fprintf(out, "capture-issue group %u %s vector_capture=legacy\n", g, test_id(V.p, V.sel[k]));
    fprintf(out, "incomplete_cycles=%u legacy_vector_captures=%u\n", V.incomplete_cycles, legacy_captures);
    fprintf(out, "status=%s partial=%s groups=%u cells=%llu minorities=%u ties=%u unstable=%u agreed_faults=%u cross_group_tests=%u worker_failures=%d\n", status,
            partial ? "yes" : "no", V.n_groups, (unsigned long long)cells, V.minorities, V.ties, V.unstable, agreed_signals + agreed_timeouts, cross, V.failures);
}

/* A short terminal explanation accompanies either report format. The detailed report keeps
 * all findings; the terminal lists at most three examples and explains incomplete evidence. */
static void human_summary(FILE *out, const char *status, int partial, uint64_t elapsed,
                          uint32_t agreed_signals, uint32_t agreed_timeouts,
                          uint32_t ungraded_groups, uint32_t legacy_captures) {
    const struct options *o = V.o;
    uint64_t completed = 0, requested = (uint64_t)V.n_sel * V.n * (uint64_t)o->rounds;
    int unfinished = 0;
    for (uint32_t wi = 0; wi < V.n; wi++) completed += V.slots[wi].cycles;
    for (uint32_t g = 0; g < V.n_groups; g++)
        unfinished |= V.g[g].next_round < (uint32_t)o->rounds;
    summary_status(out, o, status, partial, elapsed);
    fprintf(out, "Completed %llu/%llu test checks (%u test%s, %u CPU%s, %d round%s, %d execution%s per check).\n",
            (unsigned long long)completed, (unsigned long long)requested, V.n_sel, V.n_sel == 1 ? "" : "s",
            V.n, V.n == 1 ? "" : "s", o->rounds, o->rounds == 1 ? "" : "s", o->repeats, o->repeats == 1 ? "" : "s");
    if (!partial && !V.minorities && !V.ties && !V.unstable && !V.references && !V.dropped_findings)
        fputs("No disagreements, unstable tests or worker failures.\n", out);
    else fprintf(out, "Findings: %u minorities, %u ties, %u unstable results, %u reference mismatches.\n",
                 V.minorities, V.ties, V.unstable, V.references);
    for (uint32_t i = 0; i < V.n_findings && i < 3; i++) {
        const struct finding *f = &V.findings[i];
        const char *id = test_id(V.p, V.sel[f->test]);
        if (f->kind == F_MINORITY || f->kind == F_UNSTABLE)
            fprintf(out, "  %s: CPU %u, test %s, round %u.\n", kind_names[f->kind], f->cpu, id, f->round + 1);
        else fprintf(out, "  %s: group %u, test %s, round %u.\n", kind_names[f->kind], f->group, id, f->round + 1);
    }
    if (partial) {
        const char *sep = " ";
        fputs("Partial:", out);
#define REASON(...) do { fputs(sep, out); fprintf(out, __VA_ARGS__); sep = "; "; } while (0)
        if (V.budget_expired) REASON("time budget reached");
        if (V.failures) REASON("%d worker failures", V.failures);
        if (ungraded_groups) REASON("%u singleton groups cannot be graded", ungraded_groups);
        if (agreed_signals) REASON("%u agreed signals", agreed_signals);
        if (agreed_timeouts) REASON("%u agreed timeouts", agreed_timeouts);
        if (V.timeouts) REASON("%llu executions exceeded the CPU-time budget", (unsigned long long)V.timeouts);
        if (V.dropped_timeouts) REASON("%u timeout diagnostics omitted", V.dropped_timeouts);
        if (legacy_captures) REASON("%u incomplete vector captures", legacy_captures);
        if (unfinished || V.incomplete_cycles) REASON("unfinished work");
#undef REASON
        fputs(".\n", out);
    }
    summary_saved(out, o);
}

/* ---- parent ------------------------------------------------------------------ */

int orchestrate(const struct options *o, const struct pack *p, const uint32_t *sel, uint32_t n_sel) {
    int *cpus;
    V.n = (uint32_t)parse_cpu_list(o->cpus, &cpus);     /* unique and allowed, or a usage error, before anything runs */
    V.o = o; V.p = p; V.sel = sel; V.n_sel = n_sel;
    if ((uint64_t)V.n * n_sel > TABLE_LIMIT / sizeof(struct cell)) die("%u CPUs x %u tests do not fit the result table; select fewer tests", V.n, n_sel);
    size_t slots_bytes = (size_t)V.n * sizeof(struct slot), cells_bytes = (size_t)V.n * n_sel * sizeof(struct cell);
    size_t size = 4096 + ((slots_bytes + 4095) & ~(size_t)4095) + cells_bytes;
    uint8_t *m = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (m == MAP_FAILED) die("mmap shared table (%zu bytes): %s", size, strerror(errno));
    V.sh = (struct shared *)m;
    V.slots = (struct slot *)(m + 4096);
    V.cells = (struct cell *)(m + 4096 + ((slots_bytes + 4095) & ~(size_t)4095));
    V.w = calloc(V.n, sizeof *V.w);
    V.g = calloc(V.n, sizeof *V.g);
    if (!V.w || !V.g) die("calloc");
    /* Group membership is fixed here, by visiting each CPU, before any worker exists: a worker
     * that later fails to start or dies still counts in its group's quorum. */
    cpu_set_t original, one;
    if (sched_getaffinity(0, sizeof original, &original) != 0) die("sched_getaffinity: %s", strerror(errno));
    for (uint32_t wi = 0; wi < V.n; wi++) {
        CPU_ZERO(&one);
        CPU_SET(cpus[wi], &one);
        if (sched_setaffinity(0, sizeof one, &one) != 0) die_usage("--cpus: CPU %d cannot be used (%s)", cpus[wi], strerror(errno));
        uint64_t ty = o->group_none ? 0 : harp_core_type();
        uint32_t g = 0;
        while (g < V.n_groups && V.g[g].type != ty) g++;
        if (g == V.n_groups) V.g[V.n_groups++].type = ty;
        V.w[wi].cpu = cpus[wi]; V.w[wi].group = (int)g; V.g[g].size++;
    }
    if (sched_setaffinity(0, sizeof original, &original) != 0) die("sched_setaffinity: %s", strerror(errno));
    uint64_t start = now_ns();
    V.sh->deadline = o->max_seconds > 0 ? start + (uint64_t)(o->max_seconds * 1e9) : 0;
    pid_t self = getpid();
    for (uint32_t wi = 0; wi < V.n; wi++) {
        if (V.sh->deadline && now_ns() >= V.sh->deadline) { V.budget_expired = 1; break; }
        STORE(&V.slots[wi].release, 1);                 /* round 0 may start */
        pid_t pid = fork();
        if (pid < 0) die("fork: %s", strerror(errno));
        if (pid == 0) worker(wi, self);
        V.w[wi].pid = pid; V.w[wi].alive = 1;
    }
    /* Every worker must announce itself. */
    uint64_t stuck_ns = (uint64_t)(o->worker_wait_seconds * 1e9);
    for (uint64_t t0 = now_ns(); !V.budget_expired;) {
        int ready = 0;
        reap();
        for (uint32_t wi = 0; wi < V.n; wi++) ready += LOAD(&V.slots[wi].ready) != 0 || V.w[wi].failed;
        uint64_t now = now_ns();
        if (V.sh->deadline && now >= V.sh->deadline) { V.budget_expired = 1; break; }
        if (ready == (int)V.n) break;
        if (now - t0 > stuck_ns) {
            for (uint32_t wi = 0; wi < V.n; wi++) if (!LOAD(&V.slots[wi].ready)) fail(wi, "worker did not start");
            break;
        }
        struct timespec ts = {0, 200000};
        nanosleep(&ts, NULL);
    }
    /* Parent-only bookkeeping, allocated after the fork so the workers do not carry it. */
    V.pend_cap = (uint32_t)(PENDING_BYTES / ((uint64_t)n_sel * sizeof(uint64_t)));
    if (V.pend_cap > 256) V.pend_cap = 256;
    if (V.pend_cap < 1) V.pend_cap = 1;
    for (uint32_t g = 0; g < V.n_groups; g++) {
        V.g[g].pend = calloc((size_t)V.pend_cap * n_sel, sizeof(uint64_t));
        V.g[g].pend_round = calloc(V.pend_cap, sizeof(uint32_t));
        if (!V.g[g].pend || !V.g[g].pend_round) die("calloc");
    }
    V.findings = calloc(MAX_FINDINGS, sizeof *V.findings);
    V.timeout_events = calloc(MAX_FINDINGS, sizeof *V.timeout_events);
    V.cross_diff = calloc(n_sel, 1);
    V.agreed_fault = calloc((size_t)V.n_groups * n_sel, 1);
    V.agreed_signum = calloc((size_t)V.n_groups * n_sel, sizeof(uint32_t));
    V.capture_issues = calloc((size_t)V.n_groups * n_sel, 1);
    if (!V.findings || !V.timeout_events || !V.cross_diff || !V.agreed_fault || !V.agreed_signum || !V.capture_issues) die("calloc");

    uint64_t deadline = V.sh->deadline;
    for (uint32_t wi = 0; wi < V.n; wi++) { V.w[wi].last_beat = LOAD(&V.slots[wi].heartbeat); V.w[wi].last_change_ns = V.w[wi].released_ns = now_ns(); }
    while (!V.failures && !V.budget_expired) {
        struct timespec ts = {0, 1000000};
        nanosleep(&ts, NULL);
        reap();
        int all_voted = 1;
        for (uint32_t g = 0; g < V.n_groups; g++) {
            while (V.g[g].next_round < (uint32_t)o->rounds && round_published(g, V.g[g].next_round)) {
                vote(g, V.g[g].next_round);             /* reads the cells, then lets the group overwrite them */
                for (uint32_t wi = 0; wi < V.n; wi++) if (V.w[wi].group == (int)g) { STORE(&V.slots[wi].release, (uint64_t)V.g[g].next_round + 1); V.w[wi].released_ns = now_ns(); }
            }
            if (V.g[g].next_round < (uint32_t)o->rounds) all_voted = 0;
        }
        uint64_t now = now_ns();
        if (deadline && now >= deadline) { V.budget_expired = 1; break; }
        if (all_voted) break;
        for (uint32_t wi = 0; wi < V.n; wi++) {         /* liveness: a heartbeat per execution while in a round, an ack after a release */
            struct worker *w = &V.w[wi];
            struct slot *s = &V.slots[wi];
            if (!w->alive || w->failed) continue;
            uint64_t beat = LOAD(&s->heartbeat), done = LOAD(&s->done), ack = LOAD(&s->ack);
            if (beat != w->last_beat) { w->last_beat = beat; w->last_change_ns = now; }
            char why[96];
            if (ack > done && now - w->last_change_ns > stuck_ns) {
                snprintf(why, sizeof why, "no heartbeat for %llu ms", (unsigned long long)((now - w->last_change_ns) / 1000000ull));
                fail(wi, why);
            } else if (ack == done && done < (uint64_t)o->rounds && LOAD(&s->release) > done && now - w->released_ns > stuck_ns) {
                fail(wi, "did not start a released round");
            } else if (ack == done) w->last_change_ns = now;
        }
    }
    /* Stop cooperatively, then kill and reap without any unbounded waitpid. Unreaped
     * workers retain their mappings; their mutable cells are excluded from final retention. */
    STORE(&V.sh->stop, 1);
    for (uint32_t wi = 0; wi < V.n; wi++) if (V.w[wi].failed && V.w[wi].alive) kill(V.w[wi].pid, SIGKILL);
    int killed = 0;
    for (uint64_t t0 = now_ns();;) {
        reap();
        int alive = 0;
        for (uint32_t wi = 0; wi < V.n; wi++) alive += V.w[wi].alive;
        if (!alive) break;
        uint64_t waited = now_ns() - t0;
        if (!killed && waited >= 1000000000ull) {
            for (uint32_t wi = 0; wi < V.n; wi++) if (V.w[wi].alive) {
                struct worker *w = &V.w[wi];
                /* Cleanup of a healthy peer is cancellation, not another failure. */
                if (kill(w->pid, SIGKILL) == 0 && !w->failed) w->cancelled = 1;
            }
            killed = 1;
        }
        if (waited >= 2000000000ull) {
            for (uint32_t wi = 0; wi < V.n; wi++) if (V.w[wi].alive) fail(wi, "worker did not exit after SIGKILL");
            break;
        }
        struct timespec ts = {0, 1000000};
        nanosleep(&ts, NULL);
    }
    /* Every safely published observation remains evidence, including completed columns in
     * a failed group's unfinished round and repeats interrupted by the stop request. */
    for (uint32_t g = 0; g < V.n_groups; g++) {
        if (V.g[g].next_round >= (uint32_t)o->rounds) continue;
        int all_reaped = 1;
        for (uint32_t wi = 0; wi < V.n; wi++) if (V.w[wi].group == (int)g && V.w[wi].alive) all_reaped = 0;
        if (all_reaped && round_published(g, V.g[g].next_round)) vote(g, V.g[g].next_round);
        else retain_partial_round(g, V.g[g].next_round);
    }
    uint64_t elapsed = now_ns() - start;

    uint32_t cross = 0, agreed_signals = 0, agreed_timeouts = 0, ungraded_groups = 0, legacy_captures = 0;
    int incomplete = 0;
    for (uint32_t k = 0; k < n_sel; k++) cross += V.cross_diff[k];
    for (uint32_t g = 0; g < V.n_groups; g++) {
        if (V.g[g].size < 2) ungraded_groups++;
        if (V.g[g].next_round < (uint32_t)o->rounds) incomplete = 1;
        for (uint32_t k = 0; k < n_sel; k++) { uint8_t a = V.agreed_fault[(size_t)g * n_sel + k]; agreed_signals += a == 1; agreed_timeouts += a == 2; legacy_captures += V.capture_issues[(size_t)g * n_sel + k] != 0; }
    }
    int findings = V.minorities || V.ties || V.unstable || V.references || V.dropped_findings;
    int partial = incomplete || V.failures || V.budget_expired || ungraded_groups || agreed_signals || agreed_timeouts || V.timeouts || V.incomplete_cycles || legacy_captures;
    const char *status = findings ? "mismatch" : partial ? "partial" : "passed";
    FILE *out = out_open(o);
    report(out, status, partial, elapsed, cross, agreed_signals, agreed_timeouts, ungraded_groups, legacy_captures);
    FILE *summary = summary_output(out, o);
    human_summary(summary, status, partial, elapsed, agreed_signals, agreed_timeouts, ungraded_groups, legacy_captures);
    out_close(summary);
    return findings ? EXIT_MISMATCH : partial ? EXIT_PARTIAL : EXIT_OK;
}
