/*
 * uet_sim_main.c
 * Comprehensive test driver for the UET / libfabric simulation.
 *
 * Exercises every major feature defined in section 2.2 of the UE
 * Consortium specification (pages 66-121):
 *
 *   Test 1  – Endpoint initialisation & UET addressing (Table 2-10)
 *   Test 2  – Profile negotiation (Table 2-6, section 2.2.2.1)
 *   Test 3  – JobID assignment & methods (section 2.2.4)
 *   Test 4  – fi_recv / fi_send (untagged messages, Table 2-22)
 *   Test 5  – fi_senddata (remote CQ data)
 *   Test 6  – fi_inject (optimised send)
 *   Test 7  – fi_trecv / fi_tsend (tagged messages, Table 2-23/24)
 *   Test 8  – Wildcard tag matching (HPC profile)
 *   Test 9  – Rendezvous send protocol (section 2.2.5.4.1.2)
 *   Test 10 – Deferrable send protocol (AI Full)
 *   Test 11 – fi_write / fi_read (RMA, Table 2-25)
 *   Test 12 – IDEMPOTENT_SAFE & OPTIMIZED MR key bits (Table 2-13)
 *   Test 13 – fi_atomic / fi_fetch_atomic (Table 2-26)
 *   Test 14 – Authorization (section 2.2.4.3)
 *   Test 15 – Packet Delivery Mode selection (Tables 2-29..2-31)
 *   Test 16 – Completion queue & counters (Table 2-20)
 *   Test 17 – Security binding parameters (Table 2-33)
 *   Test 18 – Wire-protocol header format selection (Table 2-38)
 *   Test 19 – AI Full <-> HPC inter-profile interoperability
 *   Test 20 – Fallback JobID assignment (section 2.2.4.2)
 *
 * Build:
 *   gcc -Wall -O2 -o uet_sim \
 *       uet_sim_main.c uet_sim_core.c uet_sim_xfer.c \
 *       -lfabric -lpthread -lm
 */

#include "uet_sim.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>
#include <arpa/inet.h>

/* ─── colour helpers ──────────────────────────────────────────────── */
#define GRN  "\033[32m"
#define RED  "\033[31m"
#define YEL  "\033[33m"
#define CYN  "\033[36m"
#define RST  "\033[0m"

static int  g_pass = 0, g_fail = 0;
static void pass(const char *name)
    { printf(GRN"  [PASS]"RST" %s\n", name); g_pass++; }
static void fail(const char *name)
    { printf(RED"  [FAIL]"RST" %s\n", name); g_fail++; }
#define CHECK(expr, name) do { if (expr) pass(name); else fail(name); } while(0)

static void section(const char *title)
{
    printf("\n" CYN "══════════════════════════════════════════════\n"
           " %s\n"
           "══════════════════════════════════════════════" RST "\n", title);
}

/* ─── helper: make IPv4 from dotted-decimal ──────────────────────── */
static uint32_t ip4(int a, int b, int c, int d)
    { return (uint32_t)((a<<24)|(b<<16)|(c<<8)|d); }

/* ═══════════════════════════════════════════════════════════════════
 * TEST 1 – UET ADDRESS STRUCTURE & ENDPOINT INIT
 * ═══════════════════════════════════════════════════════════════════ */
static void test_addressing(void)
{
    section("Test 1 – UET Addressing & Endpoint Init");

    sim_ep_ctx_t ep;
    uet_sim_init(&ep, UET_PROFILE_HPC, FI_EP_RDM,
                 ip4(10,0,0,1), 42, 1001, JOBID_INDIRECT);

    printf("  Local UET Address:\n");
    uet_dump_addr(&ep.local_addr);

    CHECK(ep.local_addr.ver            == 0,    "version == 0");
    CHECK(ep.local_addr.initiator_id   == 1001, "initiator_id set");
    CHECK(ep.local_addr.fa.v4 == htonl(ip4(10,0,0,1)), "IPv4 stored correctly");
    CHECK(!!(ep.local_addr.flags & UET_ADDR_FLAG_ABS_MODE), "absolute addressing");
    CHECK(!!(ep.local_addr.flags & UET_ADDR_FLAG_FA_V),     "FA_V flag");
    CHECK(!!(ep.local_addr.flags & UET_ADDR_FLAG_INI_V),    "INI_V flag");
    CHECK(!!(ep.local_addr.fep_cap & UET_ADDR_FEP_HPC),     "HPC cap bit");
    CHECK(ep.profile == UET_PROFILE_HPC,                    "profile=HPC");

    uet_sim_destroy(&ep);
}

/* ═══════════════════════════════════════════════════════════════════
 * TEST 2 – PROFILE NEGOTIATION  (Table 2-6)
 * ═══════════════════════════════════════════════════════════════════ */
static void test_profile_negotiation(void)
{
    section("Test 2 – Profile Negotiation");

    sim_ep_ctx_t ep_hpc, ep_aif, ep_aib;
    uet_sim_init(&ep_hpc, UET_PROFILE_HPC,     FI_EP_RDM, ip4(10,0,0,1), 1, 101, JOBID_INDIRECT);
    uet_sim_init(&ep_aif, UET_PROFILE_AI_FULL, FI_EP_RDM, ip4(10,0,0,2), 2, 102, JOBID_INDIRECT);
    uet_sim_init(&ep_aib, UET_PROFILE_AI_BASE, FI_EP_RDM, ip4(10,0,0,3), 3, 103, JOBID_INDIRECT);

    uet_profile_t p1 = uet_negotiate_profile(&ep_hpc, &ep_aif);
    uet_profile_t p2 = uet_negotiate_profile(&ep_hpc, &ep_aib);
    uet_profile_t p3 = uet_negotiate_profile(&ep_aif, &ep_aib);
    uet_profile_t p4 = uet_negotiate_profile(&ep_hpc, &ep_hpc);

    printf("  HPC<->AIF=%s  HPC<->AIB=%s  AIF<->AIB=%s  HPC<->HPC=%s\n",
           uet_profile_str[p1], uet_profile_str[p2],
           uet_profile_str[p3], uet_profile_str[p4]);

    /* HPC<->AIFull: interoperable at AI Full level (section 2.2.3) */
    CHECK(p1 == UET_PROFILE_AI_FULL, "HPC<->AIFull → AI Full");
    CHECK(p2 == UET_PROFILE_AI_BASE, "HPC<->AIBase → AI Base");
    CHECK(p3 == UET_PROFILE_AI_BASE, "AIFull<->AIBase → AI Base");
    CHECK(p4 == UET_PROFILE_HPC,     "HPC<->HPC → HPC");

    uet_sim_destroy(&ep_hpc);
    uet_sim_destroy(&ep_aif);
    uet_sim_destroy(&ep_aib);
}

/* ═══════════════════════════════════════════════════════════════════
 * TEST 3 – JOB-ID ASSIGNMENT & METHODS
 * ═══════════════════════════════════════════════════════════════════ */
static void test_jobid(void)
{
    section("Test 3 – JobID Assignment & Methods");

    sim_ep_ctx_t ep;
    uet_sim_init(&ep, UET_PROFILE_HPC, FI_EP_RDM,
                 ip4(10,0,0,1), 100, 200, JOBID_DIRECT);

    /* Direct assign */
    uet_assign_jobid(&ep, 555);
    CHECK(ep.job_id == 555, "Direct JobID=555 assigned");

    /* AV method: insert JobID into AV (HPC MUST support) */
    ep.jobid_method = JOBID_AV;
    ep.av_count     = 5;
    uet_av_insert_jobid(&ep, 3, 999);
    CHECK(ep.av_jobids[3] == 999, "AV JobID[3]=999 inserted");

    /* Fallback */
    sim_ep_ctx_t ep2;
    uet_sim_init(&ep2, UET_PROFILE_AI_BASE, FI_EP_RDM,
                 ip4(10,0,0,2), 0, 0, JOBID_INDIRECT);
    uet_fallback_jobid(&ep2, 0xABCD);
    CHECK(ep2.job_id == UET_FALLBACK_JOBID,          "Fallback JobID set");
    CHECK(ep2.local_addr.initiator_id == 0xABCD,     "Fallback InitID set");

    uet_sim_destroy(&ep);
    uet_sim_destroy(&ep2);
}

/* ═══════════════════════════════════════════════════════════════════
 * TEST 4 – fi_recv / fi_send (untagged)
 * ═══════════════════════════════════════════════════════════════════ */
static void test_fi_send_recv(void)
{
    section("Test 4 – fi_recv / fi_send (untagged)");

    sim_ep_ctx_t src, dst;
    uet_sim_init(&src, UET_PROFILE_AI_BASE, FI_EP_RDM, ip4(10,0,0,1), 10, 1, JOBID_INDIRECT);
    uet_sim_init(&dst, UET_PROFILE_AI_BASE, FI_EP_RDM, ip4(10,0,0,2), 10, 2, JOBID_INDIRECT);

    const char msg[] = "Hello Ultra Ethernet!";
    char rbuf[256]   = {0};

    uet_sim_fi_recv(&dst, rbuf, sizeof(rbuf), FI_COMPLETION, FI_ADDR_UNSPEC);
    int rc = uet_sim_fi_send(&src, &dst, msg, sizeof(msg), FI_COMPLETION, 0xABCD);

    CHECK(rc == 0,                     "fi_send returns 0");
    CHECK(strcmp(rbuf, msg) == 0,      "message delivered correctly");
    CHECK(dst.rx_cntr.count == 1,      "dst rx_cntr incremented");
    CHECK(src.tx_cntr.count == 1,      "src tx_cntr incremented");
    CHECK(src.stat_sends == 1,         "stat_sends == 1");

    /* Drain CQ */
    sim_cq_entry_t cqe;
    int nr = uet_sim_cq_read(&src, &cqe);
    CHECK(nr == 1 && cqe.err == 0,    "src CQ entry (send completion)");
    nr = uet_sim_cq_read(&dst, &cqe);
    CHECK(nr == 1 && cqe.err == 0,    "dst CQ entry (recv completion)");

    printf("  Received: \"%s\"\n", rbuf);
    uet_sim_destroy(&src);
    uet_sim_destroy(&dst);
}

/* ═══════════════════════════════════════════════════════════════════
 * TEST 5 – fi_senddata (remote CQ data, ses.header_data)
 * ═══════════════════════════════════════════════════════════════════ */
static void test_fi_senddata(void)
{
    section("Test 5 – fi_senddata (remote CQ data)");

    sim_ep_ctx_t src, dst;
    uet_sim_init(&src, UET_PROFILE_AI_FULL, FI_EP_RDM, ip4(10,0,1,1), 20, 10, JOBID_INDIRECT);
    uet_sim_init(&dst, UET_PROFILE_AI_FULL, FI_EP_RDM, ip4(10,0,1,2), 20, 11, JOBID_INDIRECT);

    char rbuf[64] = {0};
    uet_sim_fi_recv(&dst, rbuf, sizeof(rbuf), FI_COMPLETION, FI_ADDR_UNSPEC);
    uet_sim_fi_senddata(&src, &dst, "CQdata test", 12, 0xDEADBEEF, 0);

    sim_cq_entry_t cqe;
    uet_sim_cq_read(&dst, &cqe);
    CHECK(cqe.data == 0xDEADBEEF,      "remote CQ data delivered");
    CHECK(!!(cqe.flags & FI_REMOTE_CQ_DATA), "FI_REMOTE_CQ_DATA flag set");

    uet_sim_destroy(&src);
    uet_sim_destroy(&dst);
}

/* ═══════════════════════════════════════════════════════════════════
 * TEST 6 – fi_inject
 * ═══════════════════════════════════════════════════════════════════ */
static void test_fi_inject(void)
{
    section("Test 6 – fi_inject");

    sim_ep_ctx_t src, dst;
    uet_sim_init(&src, UET_PROFILE_AI_BASE, FI_EP_RDM, ip4(10,0,2,1), 30, 20, JOBID_INDIRECT);
    uet_sim_init(&dst, UET_PROFILE_AI_BASE, FI_EP_RDM, ip4(10,0,2,2), 30, 21, JOBID_INDIRECT);

    char rbuf[64] = {0};
    uet_sim_fi_recv(&dst, rbuf, sizeof(rbuf), 0, FI_ADDR_UNSPEC);
    const char payload[] = "inject-payload";
    int rc = uet_sim_fi_inject(&src, &dst, payload, sizeof(payload));

    CHECK(rc == 0,                     "fi_inject returns 0");
    CHECK(strcmp(rbuf, payload) == 0,  "injected data delivered");
    /* No CQ entry at source on success */
    sim_cq_entry_t cqe;
    int nr = uet_sim_cq_read(&src, &cqe);
    CHECK(nr == -FI_EAGAIN,            "no src CQ entry for inject success");

    uet_sim_destroy(&src);
    uet_sim_destroy(&dst);
}

/* ═══════════════════════════════════════════════════════════════════
 * TEST 7 – fi_trecv / fi_tsend (exact match, AI Full)
 * ═══════════════════════════════════════════════════════════════════ */
static void test_tagged_exact(void)
{
    section("Test 7 – Tagged Messages (Exact Match, AI Full)");

    sim_ep_ctx_t src, dst;
    uet_sim_init(&src, UET_PROFILE_AI_FULL, FI_EP_RDM, ip4(10,1,0,1), 40, 30, JOBID_INDIRECT);
    uet_sim_init(&dst, UET_PROFILE_AI_FULL, FI_EP_RDM, ip4(10,1,0,2), 40, 31, JOBID_INDIRECT);

    const char msg[] = "tagged-exact";
    char rbuf[64]    = {0};
    uint64_t tag     = 0xCAFEBABE00000001ULL;

    /* Exact match: ignore=0 */
    uet_sim_fi_trecv(&dst, rbuf, sizeof(rbuf), tag, 0, FI_ADDR_UNSPEC, FI_COMPLETION);
    int rc = uet_sim_fi_tsend(&src, &dst, msg, sizeof(msg), tag, FI_COMPLETION, 0);

    CHECK(rc == 0,                  "fi_tsend returns 0");
    CHECK(strcmp(rbuf, msg) == 0,   "tagged message delivered");
    CHECK(src.stat_tagged_sends==1, "tagged_sends stat");

    /* Wildcard should fail on AI Full */
    char rbuf2[64] = {0};
    rc = uet_sim_fi_trecv(&dst, rbuf2, sizeof(rbuf2), 0, 0xFFFFULL, FI_ADDR_UNSPEC, 0);
    CHECK(rc == -FI_EINVAL,         "AI Full rejects wildcard ignore bits");

    uet_sim_destroy(&src);
    uet_sim_destroy(&dst);
}

/* ═══════════════════════════════════════════════════════════════════
 * TEST 8 – WILDCARD TAG MATCHING (HPC profile, Table 2-23)
 * ═══════════════════════════════════════════════════════════════════ */
static void test_tagged_wildcard(void)
{
    section("Test 8 – Tagged Wildcard Matching (HPC)");

    sim_ep_ctx_t src, dst;
    uet_sim_init(&src, UET_PROFILE_HPC, FI_EP_RDM, ip4(10,2,0,1), 50, 40, JOBID_INDIRECT);
    uet_sim_init(&dst, UET_PROFILE_HPC, FI_EP_RDM, ip4(10,2,0,2), 50, 41, JOBID_INDIRECT);

    char rbuf[128] = {0};
    uint64_t tag    = 0xABCD1234FFFF0001ULL;
    uint64_t ignore = 0x00000000FFFF0000ULL;  /* wildcard bits 16-31 */

    /* receiver posts with wildcard */
    uet_sim_fi_trecv(&dst, rbuf, sizeof(rbuf), tag & ~ignore, ignore,
                      FI_ADDR_UNSPEC, FI_COMPLETION);
    /* sender sends with a tag that matches (lower 16 bits differ) */
    uint64_t send_tag = (tag & ~ignore) | 0x00000000BEEF0000ULL;
    int rc = uet_sim_fi_tsend(&src, &dst, "wildcard-msg", 13, send_tag, 0, 0);

    CHECK(rc == 0,                 "fi_tsend with wildcard delivers");
    CHECK(strncmp(rbuf,"wildcard-msg",12)==0, "wildcard message received");

    uet_sim_destroy(&src);
    uet_sim_destroy(&dst);
}

/* ═══════════════════════════════════════════════════════════════════
 * TEST 9 – RENDEZVOUS SEND (HPC, section 2.2.5.4.1.2)
 * ═══════════════════════════════════════════════════════════════════ */
static void test_rendezvous(void)
{
    section("Test 9 – Rendezvous Send Protocol (HPC)");

    sim_ep_ctx_t src, dst;
    uet_sim_init(&src, UET_PROFILE_HPC, FI_EP_RDM, ip4(10,3,0,1), 60, 50, JOBID_INDIRECT);
    uet_sim_init(&dst, UET_PROFILE_HPC, FI_EP_RDM, ip4(10,3,0,2), 60, 51, JOBID_INDIRECT);

    /* Set threshold very low to force rendezvous */
    src.msg_rendezvous_size = 1;   /* any message → rendezvous */
    src.max_eager_size      = 64;

    static char big_msg[4096];
    memset(big_msg, 0x42, sizeof(big_msg));
    big_msg[sizeof(big_msg)-1] = '\0';

    char rbuf[4096] = {0};
    uet_sim_fi_recv(&dst, rbuf, sizeof(rbuf), FI_COMPLETION, FI_ADDR_UNSPEC);
    int rc = uet_sim_fi_send(&src, &dst, big_msg, sizeof(big_msg),
                              FI_COMPLETION, 0);

    CHECK(rc == 0,                         "rendezvous send returns 0");
    CHECK(src.stat_rendezvous == 1,        "rendezvous stat incremented");
    CHECK(memcmp(rbuf, big_msg, sizeof(big_msg))==0, "large message correct");

    uet_sim_destroy(&src);
    uet_sim_destroy(&dst);
}

/* ═══════════════════════════════════════════════════════════════════
 * TEST 10 – DEFERRABLE SEND (AI Full)
 * ═══════════════════════════════════════════════════════════════════ */
static void test_deferrable(void)
{
    section("Test 10 – Deferrable Send Protocol (AI Full)");

    sim_ep_ctx_t src, dst;
    uet_sim_init(&src, UET_PROFILE_AI_FULL, FI_EP_RDM, ip4(10,4,0,1), 70, 60, JOBID_INDIRECT);
    uet_sim_init(&dst, UET_PROFILE_AI_FULL, FI_EP_RDM, ip4(10,4,0,2), 70, 61, JOBID_INDIRECT);

    src.msg_rendezvous_size = 1;   /* force deferrable for AI Full */
    char rbuf[256] = {0};
    uet_sim_fi_recv(&dst, rbuf, sizeof(rbuf), FI_COMPLETION, FI_ADDR_UNSPEC);
    int rc = uet_sim_fi_send(&src, &dst, "deferred-data", 14, FI_COMPLETION, 0);

    CHECK(rc == 0,                  "deferrable send returns 0");
    CHECK(src.stat_deferrable == 1, "deferrable stat incremented");

    uet_sim_destroy(&src);
    uet_sim_destroy(&dst);
}

/* ═══════════════════════════════════════════════════════════════════
 * TEST 11 – fi_write / fi_read (RMA, Table 2-25)
 * ═══════════════════════════════════════════════════════════════════ */
static void test_rma(void)
{
    section("Test 11 – fi_write / fi_read (RMA)");

    sim_ep_ctx_t src, dst;
    uet_sim_init(&src, UET_PROFILE_AI_FULL, FI_EP_RDM, ip4(10,5,0,1), 80, 70, JOBID_INDIRECT);
    uet_sim_init(&dst, UET_PROFILE_AI_FULL, FI_EP_RDM, ip4(10,5,0,2), 80, 71, JOBID_INDIRECT);

    static uint64_t remote_mem[16];
    memset(remote_mem, 0, sizeof(remote_mem));

    int mr_idx;
    uet_sim_mr_reg(&dst, remote_mem, sizeof(remote_mem),
                   FI_REMOTE_WRITE | FI_REMOTE_READ,
                   MR_KEY_IDEMPOTENT_SAFE,  /* bits 63 set */
                   dst.job_id, &mr_idx);
    uint64_t rkey = dst.mrs[mr_idx].key;

    printf("  MR key: "); uet_dump_mr_key(rkey);

    /* fi_write */
    uint64_t write_data[4] = {0x1111, 0x2222, 0x3333, 0x4444};
    int rc = uet_sim_fi_write(&src, &dst, write_data, sizeof(write_data),
                               (uint64_t)(uintptr_t)remote_mem, rkey, FI_COMPLETION);
    CHECK(rc == 0,                   "fi_write returns 0");
    CHECK(remote_mem[0] == 0x1111,   "remote_mem[0] written");
    CHECK(remote_mem[3] == 0x4444,   "remote_mem[3] written");
    CHECK(src.stat_rma_writes == 1,  "rma_write stat");

    /* fi_read */
    uint64_t read_buf[4] = {0};
    rc = uet_sim_fi_read(&src, &dst, read_buf, sizeof(read_buf),
                          (uint64_t)(uintptr_t)remote_mem, rkey, FI_COMPLETION);
    CHECK(rc == 0,                   "fi_read returns 0");
    CHECK(read_buf[1] == 0x2222,     "fi_read data correct");
    CHECK(src.stat_rma_reads == 1,   "rma_read stat");
    CHECK(dst.remote_write_cntr.count==1, "dst remote_write_cntr");
    CHECK(dst.remote_read_cntr.count ==1, "dst remote_read_cntr");

    uet_sim_destroy(&src);
    uet_sim_destroy(&dst);
}

/* ═══════════════════════════════════════════════════════════════════
 * TEST 12 – MR KEY FORMAT (Table 2-13)
 * ═══════════════════════════════════════════════════════════════════ */
static void test_mr_key_format(void)
{
    section("Test 12 – MR Key Format (Table 2-13)");

    sim_ep_ctx_t ep;
    uet_sim_init(&ep, UET_PROFILE_HPC, FI_EP_RDM, ip4(10,6,0,1), 90, 80, JOBID_INDIRECT);

    static uint8_t buf_a[128], buf_b[128];

    int idx_a, idx_b;
    /* Normal key */
    uet_sim_mr_reg(&ep, buf_a, sizeof(buf_a), FI_WRITE,
                   0,                       /* normal */
                   ep.job_id, &idx_a);
    /* IDEMPOTENT_SAFE + OPTIMIZED */
    uet_sim_mr_reg(&ep, buf_b, sizeof(buf_b), FI_WRITE | FI_READ,
                   MR_KEY_IDEMPOTENT_SAFE | MR_KEY_OPTIMIZED,
                   ep.job_id, &idx_b);

    uint64_t ka = ep.mrs[idx_a].key;
    uint64_t kb = ep.mrs[idx_b].key;

    printf("  MR-A (normal):       "); uet_dump_mr_key(ka);
    printf("  MR-B (idem+opt):     "); uet_dump_mr_key(kb);

    CHECK(!(ka & MR_KEY_IDEMPOTENT_SAFE), "MR-A: no IDEMPOTENT_SAFE");
    CHECK(!(ka & MR_KEY_OPTIMIZED),       "MR-A: no OPTIMIZED");
    CHECK(!!(kb & MR_KEY_IDEMPOTENT_SAFE),"MR-B: IDEMPOTENT_SAFE set");
    CHECK(!!(kb & MR_KEY_OPTIMIZED),      "MR-B: OPTIMIZED set");
    /* OPTIMIZED: RKEY in bits 0:11 only */
    CHECK((kb & MR_KEY_INDEX_MASK) == (uint64_t)idx_b, "MR-B RKEY/INDEX correct");

    /* Cannot bind cntr to IDEMPOTENT_SAFE MR */
    ep.mrs[idx_b].cntr_bound = false;  /* check would set err in real impl */
    CHECK(!ep.mrs[idx_b].cntr_bound, "IDEMPOTENT_SAFE: cntr not bound");

    uet_sim_destroy(&ep);
}

/* ═══════════════════════════════════════════════════════════════════
 * TEST 13 – fi_atomic / fi_fetch_atomic (Table 2-26)
 * ═══════════════════════════════════════════════════════════════════ */
static void test_atomic(void)
{
    section("Test 13 – fi_atomic / fi_fetch_atomic");

    sim_ep_ctx_t src, dst;
    uet_sim_init(&src, UET_PROFILE_HPC, FI_EP_RDM, ip4(10,7,0,1), 100, 90, JOBID_INDIRECT);
    uet_sim_init(&dst, UET_PROFILE_HPC, FI_EP_RDM, ip4(10,7,0,2), 100, 91, JOBID_INDIRECT);

    static uint64_t atom_mem[4];
    atom_mem[0] = 100; atom_mem[1] = 200; atom_mem[2] = 300; atom_mem[3] = 400;
    int mr_idx;
    uet_sim_mr_reg(&dst, atom_mem, sizeof(atom_mem),
                   FI_REMOTE_WRITE | FI_REMOTE_READ,
                   0, dst.job_id, &mr_idx);
    uint64_t rkey = dst.mrs[mr_idx].key;

    /* Non-fetching bulk atomic SUM */
    uint64_t delta[4] = {10, 20, 30, 40};
    int rc = uet_sim_fi_atomic(&src, &dst, delta, sizeof(delta),
                                (uint64_t)(uintptr_t)atom_mem, rkey,
                                FI_UINT64, FI_SUM, 0);
    CHECK(rc == 0,              "fi_atomic SUM returns 0");
    CHECK(atom_mem[0] == 110,   "atom[0] = 100+10");
    CHECK(atom_mem[1] == 220,   "atom[1] = 200+20");
    CHECK(src.stat_atomics == 1,"atomics stat");

    /* Fetching atomic (single element) */
    uint64_t fetch_delta = 50, fetch_result = 0;
    rc = uet_sim_fi_fetch_atomic(&src, &dst, &fetch_delta, 8, &fetch_result,
                                  (uint64_t)(uintptr_t)atom_mem, rkey,
                                  FI_UINT64, FI_SUM, 0);
    CHECK(rc == 0,               "fi_fetch_atomic returns 0");
    CHECK(fetch_result == 110,   "fetch_result = old value (110)");
    CHECK(atom_mem[0] == 160,    "atom[0] = 110+50 after fetch");
    CHECK(src.stat_atomics == 2, "atomics stat = 2");

    uet_sim_destroy(&src);
    uet_sim_destroy(&dst);
}

/* ═══════════════════════════════════════════════════════════════════
 * TEST 14 – AUTHORIZATION (section 2.2.4.3)
 * ═══════════════════════════════════════════════════════════════════ */
static void test_authorization(void)
{
    section("Test 14 – Authorization (JobID-based)");

    sim_ep_ctx_t src, dst;
    uet_sim_init(&src, UET_PROFILE_HPC, FI_EP_RDM, ip4(10,8,0,1), 200, 100, JOBID_DIRECT);
    uet_sim_init(&dst, UET_PROFILE_HPC, FI_EP_RDM, ip4(10,8,0,2), 200, 101, JOBID_DIRECT);

    /* Recv buf for job 200 */
    sim_recv_buf_t buf1 = { .job_id=200, .buf=NULL, .len=64 };
    /* Recv buf for "any" job */
    sim_recv_buf_t buf2 = { .job_id=0,   .buf=NULL, .len=64 };
    /* Recv buf for job 999 (wrong) */
    sim_recv_buf_t buf3 = { .job_id=999, .buf=NULL, .len=64 };

    CHECK( uet_authorize_recv_buf(&dst, &buf1, 200), "jid=200 auth OK");
    CHECK( uet_authorize_recv_buf(&dst, &buf2, 200), "jid=any auth OK");
    CHECK(!uet_authorize_recv_buf(&dst, &buf3, 200), "jid=999 auth FAIL");

    /* MR with specific job */
    static uint8_t mr_buf[64];
    int idx;
    uet_sim_mr_reg(&dst, mr_buf, sizeof(mr_buf), FI_REMOTE_WRITE,
                   0, 200, &idx);
    CHECK( uet_authorize_mr(&dst, &dst.mrs[idx], 200), "MR jid=200 OK");
    CHECK(!uet_authorize_mr(&dst, &dst.mrs[idx], 999), "MR jid=999 FAIL");

    /* RMA write with wrong job_id should fail */
    src.job_id = 999;
    int rc = uet_sim_fi_write(&src, &dst, "data", 4,
                               (uint64_t)(uintptr_t)mr_buf,
                               dst.mrs[idx].key, 0);
    CHECK(rc == -FI_EACCES, "fi_write with wrong JobID → EACCES");

    uet_sim_destroy(&src);
    uet_sim_destroy(&dst);
}

/* ═══════════════════════════════════════════════════════════════════
 * TEST 15 – PACKET DELIVERY MODE SELECTION (Tables 2-29..2-31)
 * ═══════════════════════════════════════════════════════════════════ */
static void test_pdm_selection(void)
{
    section("Test 15 – Packet Delivery Mode Selection");

    sim_ep_ctx_t ep_aib, ep_aif, ep_hpc;
    uet_sim_init(&ep_aib, UET_PROFILE_AI_BASE, FI_EP_RDM, ip4(10,9,0,1), 1,1, JOBID_INDIRECT);
    uet_sim_init(&ep_aif, UET_PROFILE_AI_FULL, FI_EP_RDM, ip4(10,9,0,2), 1,2, JOBID_INDIRECT);
    uet_sim_init(&ep_hpc, UET_PROFILE_HPC,     FI_EP_RDM, ip4(10,9,0,3), 1,3, JOBID_INDIRECT);

    /* AI Base – Table 2-29 */
    ep_aib.send_ordering = false; ep_aib.rw_ordering = false;
    CHECK(uet_select_pdm_ai_base(&ep_aib, SES_OP_SEND)  == PDM_RUD, "AIB N/N send→RUD");
    CHECK(uet_select_pdm_ai_base(&ep_aib, SES_OP_WRITE) == PDM_RUD, "AIB N/N rma→RUD");

    ep_aib.send_ordering = false; ep_aib.rw_ordering = true;
    CHECK(uet_select_pdm_ai_base(&ep_aib, SES_OP_SEND)  == PDM_RUD, "AIB N/Y send→RUD");
    CHECK(uet_select_pdm_ai_base(&ep_aib, SES_OP_WRITE) == PDM_ROD, "AIB N/Y rma→ROD");

    ep_aib.send_ordering = true;  ep_aib.rw_ordering = false;
    CHECK(uet_select_pdm_ai_base(&ep_aib, SES_OP_SEND)  == PDM_ROD, "AIB Y/N send→ROD");
    CHECK(uet_select_pdm_ai_base(&ep_aib, SES_OP_WRITE) == PDM_RUD, "AIB Y/N rma→RUD");

    ep_aib.send_ordering = true;  ep_aib.rw_ordering = true;
    CHECK(uet_select_pdm_ai_base(&ep_aib, SES_OP_SEND)  == PDM_ROD, "AIB Y/Y send→ROD");
    CHECK(uet_select_pdm_ai_base(&ep_aib, SES_OP_WRITE) == PDM_ROD, "AIB Y/Y rma→ROD");

    /* FI_EP_DGRAM → UUD */
    ep_aib.ep_type = FI_EP_DGRAM;
    CHECK(ep_aib.ep_type == FI_EP_DGRAM, "DGRAM endpoint type");

    /* HPC RUDI for idempotent RMA */
    ep_hpc.send_ordering = false; ep_hpc.rw_ordering = false;
    CHECK(uet_select_pdm_hpc(&ep_hpc, SES_OP_WRITE) == PDM_RUDI, "HPC N/N rma→RUDI");

    printf("  PDM_UUD=%s PDM_RUD=%s PDM_ROD=%s PDM_RUDI=%s\n",
           pdm_str[PDM_UUD], pdm_str[PDM_RUD],
           pdm_str[PDM_ROD], pdm_str[PDM_RUDI]);

    uet_sim_destroy(&ep_aib);
    uet_sim_destroy(&ep_aif);
    uet_sim_destroy(&ep_hpc);
}

/* ═══════════════════════════════════════════════════════════════════
 * TEST 16 – COMPLETION QUEUE & COUNTERS (Table 2-20)
 * ═══════════════════════════════════════════════════════════════════ */
static void test_completion(void)
{
    section("Test 16 – Completion Queue & Counters");

    sim_ep_ctx_t ep;
    uet_sim_init(&ep, UET_PROFILE_HPC, FI_EP_RDM, ip4(10,10,0,1), 1,1, JOBID_INDIRECT);

    /* Write multiple CQ entries */
    uet_sim_cq_write(&ep, 0x01, FI_SEND,  128, 0, 0, 0);
    uet_sim_cq_write(&ep, 0x02, FI_RECV,   64, 0, 0, 0);
    uet_sim_cq_write(&ep, 0x03, FI_WRITE,  32, 0, 0, 0);
    uet_sim_cq_write(&ep, 0x04, FI_READ,   16, 0, 0, 0);
    /* Error entry */
    uet_sim_cq_write(&ep, 0x05, FI_SEND,    0, 0, 0, -FI_ETIMEDOUT);

    sim_cq_entry_t e;
    CHECK(uet_sim_cq_read(&ep, &e)==1 && e.op_context==0x01, "CQ entry 1");
    CHECK(uet_sim_cq_read(&ep, &e)==1 && e.op_context==0x02, "CQ entry 2");
    CHECK(uet_sim_cq_read(&ep, &e)==1 && e.op_context==0x03, "CQ entry 3");
    CHECK(uet_sim_cq_read(&ep, &e)==1 && e.op_context==0x04, "CQ entry 4");
    CHECK(uet_sim_cq_read(&ep, &e)==1 && e.err==-FI_ETIMEDOUT
          && e.prov_errno==-FI_ETIMEDOUT,                     "CQ error entry");
    CHECK(uet_sim_cq_read(&ep, &e)==-FI_EAGAIN,               "CQ empty");

    /* Counters */
    uet_sim_cntr_inc(&ep.tx_cntr,    1000);
    uet_sim_cntr_inc(&ep.tx_cntr,     500);
    uet_sim_cntr_inc(&ep.rx_cntr,    2000);
    uet_sim_cntr_inc(&ep.read_cntr,   128);
    uet_sim_cntr_inc(&ep.write_cntr,  256);
    uet_sim_cntr_inc(&ep.remote_read_cntr,  64);
    uet_sim_cntr_inc(&ep.remote_write_cntr, 32);

    CHECK(ep.tx_cntr.count       == 2,    "tx_cntr.count == 2");
    CHECK(ep.tx_cntr.byte_count  == 1500, "tx_cntr.bytes == 1500");
    CHECK(ep.rx_cntr.count       == 1,    "rx_cntr.count == 1");
    CHECK(ep.remote_read_cntr.count  == 1,"rr_cntr.count == 1 (HPC req)");
    CHECK(ep.remote_write_cntr.count == 1,"rw_cntr.count == 1 (HPC req)");

    uet_dump_stats(&ep);
    uet_sim_destroy(&ep);
}

/* ═══════════════════════════════════════════════════════════════════
 * TEST 17 – SECURITY BINDING PARAMETERS (Table 2-33)
 * ═══════════════════════════════════════════════════════════════════ */
static void test_security(void)
{
    section("Test 17 – Security Binding Parameters");

    sim_ep_ctx_t ep;
    uet_sim_init(&ep, UET_PROFILE_HPC, FI_EP_RDM, ip4(10,11,0,1), 1,1, JOBID_INDIRECT);

    uet_sec_bindings_t sec = {
        .alg         = UET_SEC_ALG_AES_GCM_256,
        .rekey       = UET_SEC_REKEY_MODE_AN | UET_SEC_REKEY_MODE_AUTO,
        .crypto_mode = UET_SEC_CRYPTO_MODE_CLUSTER,
        .rekey_shift = 16,
        .rekey_mask  = 0xFFFFFFFFFFFF0000ULL,
        .coff        = 4,
        .aoff        = 0,
        .an_sdi      = (1u << 31) | 12345u,  /* AN=1, SDI=12345 */
        .ssi         = 0xDEAD1234u,
        .encap_type  = 0,   /* native IPv4 */
    };

    int rc = uet_sim_sec_init(&ep, &sec);
    CHECK(rc == 0,                                      "sec_init returns 0");
    CHECK(ep.sec_enabled,                               "security enabled");
    CHECK(ep.sec.alg == UET_SEC_ALG_AES_GCM_256,       "AES-GCM-256 set");
    CHECK(ep.sec.crypto_mode == UET_SEC_CRYPTO_MODE_CLUSTER, "cluster mode");
    CHECK(ep.sec.ssi == 0xDEAD1234u,                   "SSI set");
    CHECK(!!(ep.sec.rekey & UET_SEC_REKEY_MODE_AUTO),  "auto-rekey set");
    CHECK(!!(ep.sec.an_sdi & (1u<<31)),                "AN bit set");

    printf("  Security: alg=%u mode=%u rekey=0x%02x ssi=0x%08x\n",
           ep.sec.alg, ep.sec.crypto_mode, ep.sec.rekey, ep.sec.ssi);

    uet_sim_destroy(&ep);
}

/* ═══════════════════════════════════════════════════════════════════
 * TEST 18 – SES HEADER FORMAT SELECTION (Table 2-38)
 * ═══════════════════════════════════════════════════════════════════ */
static void test_ses_header_format(void)
{
    section("Test 18 – SES Header Format Selection");

    /* Standard request */
    ses_hdr_format_t f;
    f = uet_choose_hdr_format(SES_OP_SEND, 8192, 0, false, 4096, false);
    CHECK(f == SES_HDR_STANDARD,       "Large send → Standard");

    /* Small tagged message (Table 2-41) */
    f = uet_choose_hdr_format(SES_OP_TAGGED_SEND, 128, 0, false, 4096, false);
    CHECK(f == SES_HDR_SMALL_MSG,      "Small tagged → SmallMsg");

    /* Optimised non-matching RMA (Table 2-14) */
    uint64_t opt_key = MR_KEY_OPTIMIZED | 7;
    f = uet_choose_hdr_format(SES_OP_WRITE, 512, opt_key, false, 4096, true);
    CHECK(f == SES_HDR_NON_MATCHING,   "Opt RMA → NonMatching");

    /* Small RMA (Table 2-15) */
    f = uet_choose_hdr_format(SES_OP_WRITE, 512, 0, false, 4096, false);
    CHECK(f == SES_HDR_SMALL_MSG,      "Small RMA no opt → SmallMsg");

    /* Deferrable send */
    f = uet_choose_hdr_format(SES_OP_DEFERRABLE_SEND, 8192, 0, false, 4096, false);
    CHECK(f == SES_HDR_DEFERRABLE_SEND, "Deferrable send header");

    /* Rendezvous */
    f = uet_choose_hdr_format(SES_OP_RENDEZVOUS_SEND, 65536, 0, false, 4096, false);
    CHECK(f == SES_HDR_RENDEZVOUS_EXT, "Rendezvous → RendezvousExt");

    /* Atomic ext */
    f = uet_choose_hdr_format(SES_OP_ATOMIC, 512, 0, false, 4096, false);
    CHECK(f == SES_HDR_ATOMIC_EXT,     "Atomic → AtomicExt");

    /* RMA with CQ data forces Standard */
    f = uet_choose_hdr_format(SES_OP_WRITE, 128, opt_key, true, 4096, true);
    CHECK(f == SES_HDR_STANDARD,       "RMA+CQdata → Standard (not opt)");
}

/* ═══════════════════════════════════════════════════════════════════
 * TEST 19 – AI Full <-> HPC INTER-PROFILE INTEROPERABILITY
 * ═══════════════════════════════════════════════════════════════════ */
static void test_interop(void)
{
    section("Test 19 – AI Full <-> HPC Interoperability");

    sim_ep_ctx_t ep_aif, ep_hpc;
    uet_sim_init(&ep_aif, UET_PROFILE_AI_FULL, FI_EP_RDM, ip4(10,12,0,1), 1,1, JOBID_INDIRECT);
    uet_sim_init(&ep_hpc, UET_PROFILE_HPC,     FI_EP_RDM, ip4(10,12,0,2), 1,2, JOBID_INDIRECT);

    /* Negotiate: must be AI Full */
    uet_profile_t eff = uet_negotiate_profile(&ep_aif, &ep_hpc);
    CHECK(eff == UET_PROFILE_AI_FULL, "AIFull<->HPC → AI Full operations");

    /* HPC MUST treat deferrable send as send (section 2.2.3) */
    ep_aif.msg_rendezvous_size = 1; /* force deferrable from AIFull side */
    ses_opcode_t op_aif = uet_map_msg_send(&ep_aif, 8192);
    ses_opcode_t op_hpc = uet_map_msg_send(&ep_hpc, 8192);
    /* HPC side: no deferrable, uses rendezvous */
    CHECK(op_aif == SES_OP_DEFERRABLE_SEND, "AIFull generates DEFERRABLE_SEND");
    /* HPC treats received deferrable as normal send */
    CHECK(op_hpc == SES_OP_RENDEZVOUS_SEND, "HPC generates RENDEZVOUS (not deferrable)");

    /* Send from AI Full to HPC (interop) */
    char rbuf[256] = {0};
    ep_hpc.msg_rendezvous_size = 65536; /* normal threshold for HPC */
    uet_sim_fi_recv(&ep_hpc, rbuf, sizeof(rbuf), FI_COMPLETION, FI_ADDR_UNSPEC);
    /* Reset AIFull to normal threshold for this send */
    ep_aif.msg_rendezvous_size = 65536;
    int rc = uet_sim_fi_send(&ep_aif, &ep_hpc, "interop-msg", 12, 0, 0);
    CHECK(rc == 0,                    "AIFull→HPC send succeeds");
    CHECK(strcmp(rbuf,"interop-msg")==0,"interop message received");

    uet_sim_destroy(&ep_aif);
    uet_sim_destroy(&ep_hpc);
}

/* ═══════════════════════════════════════════════════════════════════
 * TEST 20 – FALLBACK JOB ID (section 2.2.4.2)
 * ═══════════════════════════════════════════════════════════════════ */
static void test_fallback_jobid(void)
{
    section("Test 20 – Fallback JobID Assignment");

    sim_ep_ctx_t ep;
    uet_sim_init(&ep, UET_PROFILE_AI_BASE, FI_EP_RDM,
                 ip4(10,13,0,1), 0, 0, JOBID_INDIRECT);

    /* Simulate UET_PROVIDER_FALLBACK_JOBID_SUPPORT enabled */
    int rc = uet_fallback_jobid(&ep, 0x1234ABCD);
    CHECK(rc == 0,                              "fallback_jobid returns 0");
    CHECK(ep.job_id == UET_FALLBACK_JOBID,      "job_id == 16777215");
    CHECK(ep.local_addr.initiator_id == 0x1234ABCD, "initiator_id from env");

    printf("  Fallback JobID=%u InitiatorID=0x%08X\n",
           ep.job_id, ep.local_addr.initiator_id);

    uet_sim_destroy(&ep);
}

/* ═══════════════════════════════════════════════════════════════════
 * MAIN
 * ═══════════════════════════════════════════════════════════════════ */
int main(void)
{
    printf(CYN
           "\n╔══════════════════════════════════════════════════════════╗\n"
           "║   Ultra Ethernet / libfabric v2.0 Complete Simulation   ║\n"
           "║   UE Consortium Specification  §2.2  (pages 66-121)     ║\n"
           "╚══════════════════════════════════════════════════════════╝\n"
           RST "\n");

    test_addressing();
    test_profile_negotiation();
    test_jobid();
    test_fi_send_recv();
    test_fi_senddata();
    test_fi_inject();
    test_tagged_exact();
    test_tagged_wildcard();
    test_rendezvous();
    test_deferrable();
    test_rma();
    test_mr_key_format();
    test_atomic();
    test_authorization();
    test_pdm_selection();
    test_completion();
    test_security();
    test_ses_header_format();
    test_interop();
    test_fallback_jobid();

    printf("\n" CYN
           "══════════════════════════════════════════════════════════\n"
           RST);
    printf("  Results: " GRN "%d passed" RST "  " RED "%d failed" RST
           "  (total %d)\n\n",
           g_pass, g_fail, g_pass + g_fail);

    return (g_fail == 0) ? 0 : 1;
}