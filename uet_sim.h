/*
 * uet_sim.h  –  Ultra Ethernet Transport (UET v1.0) / libfabric v2.0 Simulation
 *
 * Simulates the full UE Consortium spec (section 2.2):
 *   • UET addressing (FI_ADDR_UET, Table 2-10)
 *   • Three profiles: AI Base, AI Full, HPC  (Table 2-4 / 2-5)
 *   • JobID management (indirect / direct / AV methods, section 2.2.4)
 *   • Authorization of receive buffers & memory regions (section 2.2.4.3)
 *   • Data-transfer APIs: fi_msg, fi_tagged, fi_rma, fi_atomic (section 2.2.5.4)
 *   • Rendezvous & deferrable-send protocols (section 2.2.5.4.1.2)
 *   • Packet Delivery Mode selection (Tables 2-29..2-31)
 *   • Completion queues & counters (Table 2-20)
 *   • Security binding parameters (Table 2-33)
 *   • Wire-protocol header mapping (section 2.2.10)
 *
 * NOTE: libfabric (rdma-core) headers are assumed to be installed.
 *       Compile with:  gcc -o uet_sim uet_sim_main.c -lfabric -lpthread -lm
 */

#ifndef UET_SIM_H
#define UET_SIM_H

#include <rdma/fabric.h>
#include <rdma/fi_domain.h>
#include <rdma/fi_endpoint.h>
#include <rdma/fi_eq.h>

#include <rdma/fi_tagged.h>
#include <rdma/fi_rma.h>
#include <rdma/fi_atomic.h>
#include <rdma/fi_cm.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include <time.h>

/* ═══════════════════════════════════════════════════════════════════
 *  UET PROFILE DEFINITIONS  (section 2.2.2)
 * ═══════════════════════════════════════════════════════════════════ */
typedef enum {
    UET_PROFILE_AI_BASE = 0,   /* logical priority 0 */
    UET_PROFILE_AI_FULL = 1,   /* logical priority 1 */
    UET_PROFILE_HPC     = 2,   /* logical priority 2 */
    UET_PROFILE_MAX
} uet_profile_t;

__attribute__((unused))
static const char *uet_profile_str[] = {
    [UET_PROFILE_AI_BASE] = "AI Base",
    [UET_PROFILE_AI_FULL] = "AI Full",
    [UET_PROFILE_HPC]     = "HPC",
};

/* ═══════════════════════════════════════════════════════════════════
 *  UET ADDRESS STRUCTURE  (Table 2-10)
 * ═══════════════════════════════════════════════════════════════════ */
/* Flags field bits */
#define UET_ADDR_FLAG_FEP_CAP_V    (1 << 0)   /* FEP capabilities valid */
#define UET_ADDR_FLAG_FA_V         (1 << 1)   /* fabric address valid   */
#define UET_ADDR_FLAG_PID_V        (1 << 2)   /* PIDonFEP valid         */
#define UET_ADDR_FLAG_RI_V         (1 << 3)   /* resource index valid   */
#define UET_ADDR_FLAG_INI_V        (1 << 4)   /* initiator ID valid     */
#define UET_ADDR_FLAG_ABS_MODE     (1 << 5)   /* absolute addressing    */
#define UET_ADDR_FLAG_REL_MODE     (0 << 5)   /* relative addressing    */
#define UET_ADDR_FLAG_IPV6         (1 << 6)   /* IPv6 fabric address    */
#define UET_ADDR_FLAG_IPV4         (0 << 6)   /* IPv4 fabric address    */
#define UET_ADDR_FLAG_MTU_MSG_SIZE (1 << 7)   /* max msg size = MTU     */

/* Fabric Endpoint Capabilities field bits */
#define UET_ADDR_FEP_AI_BASE       (1 << 0)   /* AI Base profile        */
#define UET_ADDR_FEP_AI_FULL       (1 << 1)   /* AI Full profile        */
#define UET_ADDR_FEP_HPC           (1 << 2)   /* HPC profile            */
#define UET_ADDR_FEP_OPT_NM_SEM   (1 << 7)   /* optimised non-matching  */

/* Fabric address (IPv4 or IPv6) */
struct uet_fa {
    union {
        uint32_t v4;
        uint8_t  v6[16];
    };
};

/* Full UET libfabric endpoint address (version 0) */
struct uet_addr {
    uint8_t          ver;                /* must be 0               */
    uint8_t          reserved;           /* alignment               */
    uint16_t         flags;              /* UET_ADDR_FLAG_*         */
    uint16_t         fep_cap;            /* UET_ADDR_FEP_*          */
    uint16_t         pid_on_fep;         /* PIDonFEP                */
    struct uet_fa    fa;                 /* IP address (128-bit)    */
    uint16_t         start_resource_idx; /* service identifier      */
    uint16_t         num_resource_idx;   /* sequential indices      */
    uint32_t         initiator_id;       /* initiator ID            */
};

/* ═══════════════════════════════════════════════════════════════════
 *  PACKET DELIVERY MODES  (section 2.2.6)
 * ═══════════════════════════════════════════════════════════════════ */
typedef enum {
    PDM_UUD  = 0,  /* Unreliable Unordered Datagram (FI_EP_DGRAM)  */
    PDM_RUD  = 1,  /* Reliable Unordered Datagram                   */
    PDM_ROD  = 2,  /* Reliable Ordered Datagram                     */
    PDM_RUDI = 3,  /* Reliable Unordered Datagram – Idempotent (HPC)*/
} uet_pdm_t;

__attribute__((unused))
static const char *pdm_str[] = {
    [PDM_UUD]  = "UUD",
    [PDM_RUD]  = "RUD",
    [PDM_ROD]  = "ROD",
    [PDM_RUDI] = "RUDI",
};

/* ═══════════════════════════════════════════════════════════════════
 *  SES SEMANTIC OPCODES  (section 2.2.5.4)
 * ═══════════════════════════════════════════════════════════════════ */
typedef enum {
    SES_OP_DATAGRAM_SEND        = 0x01,
    SES_OP_SEND                 = 0x02,
    SES_OP_DEFERRABLE_SEND      = 0x03,
    SES_OP_RENDEZVOUS_SEND      = 0x04,
    SES_OP_TAGGED_SEND          = 0x05,
    SES_OP_DEFERRABLE_TSEND     = 0x06,
    SES_OP_RENDEZVOUS_TSEND     = 0x07,
    SES_OP_READ                 = 0x08,
    SES_OP_WRITE                = 0x09,
    SES_OP_ATOMIC               = 0x0A,
    SES_OP_TSEND_ATOMIC         = 0x0B,
    SES_OP_FETCHING_ATOMIC      = 0x0C,
} ses_opcode_t;

__attribute__((unused))
static const char *ses_op_str[] = {
    [SES_OP_DATAGRAM_SEND]    = "UET_DATAGRAM_SEND",
    [SES_OP_SEND]             = "UET_SEND",
    [SES_OP_DEFERRABLE_SEND]  = "UET_DEFERRABLE_SEND",
    [SES_OP_RENDEZVOUS_SEND]  = "UET_RENDEZVOUS_SEND",
    [SES_OP_TAGGED_SEND]      = "UET_TAGGED_SEND",
    [SES_OP_DEFERRABLE_TSEND] = "UET_DEFERRABLE_TSEND",
    [SES_OP_RENDEZVOUS_TSEND] = "UET_RENDEZVOUS_TSEND",
    [SES_OP_READ]             = "UET_READ",
    [SES_OP_WRITE]            = "UET_WRITE",
    [SES_OP_ATOMIC]           = "UET_ATOMIC",
    [SES_OP_TSEND_ATOMIC]     = "UET_TSEND_ATOMIC",
    [SES_OP_FETCHING_ATOMIC]  = "UET_FETCHING_ATOMIC",
};

/* ═══════════════════════════════════════════════════════════════════
 *  SES WIRE HEADER  (section 2.2.10.4 / Table 2-39)
 * ═══════════════════════════════════════════════════════════════════ */
typedef enum {
    SES_HDR_STANDARD         = 0,
    SES_HDR_NON_MATCHING     = 1,  /* optimised non-matching          */
    SES_HDR_SMALL_MSG        = 2,  /* small message / small RMA       */
    SES_HDR_DEFERRABLE_SEND  = 3,
    SES_HDR_READY_TO_RESTART = 4,
    SES_HDR_RENDEZVOUS_EXT   = 5,
    SES_HDR_ATOMIC_EXT       = 6,
    SES_HDR_COMPARE_SWAP     = 7,
    SES_HDR_RESPONSE         = 8,
} ses_hdr_format_t;

/* Simulated standard SES request header */
typedef struct {
    ses_hdr_format_t format;
    ses_opcode_t     opcode;
    bool             delivery_complete;  /* dc bit */
    bool             relative;           /* rel bit */
    bool             header_data_present;/* hd bit  */
    uint16_t         resource_index;
    uint8_t          ri_generation;
    uint32_t         job_id;
    uint16_t         pid_on_fep;
    uint64_t         buffer_offset;
    uint32_t         initiator;
    uint64_t         match_bits;         /* MR key or tag */
    uint64_t         header_data;        /* remote CQ data */
    uint32_t         request_length;
    /* rendezvous extension */
    uint32_t         eager_length;
    uint16_t         read_pid_on_fep;
    uint16_t         read_resource_index;
    uint64_t         read_offset;
    uint64_t         read_memory_key;
    /* deferrable send restart tokens */
    uint32_t         initiator_restart_token;
    uint32_t         target_restart_token;
    /* atomic extension */
    uint8_t          atomic_opcode;
    uint8_t          atomic_datatype;
    uint64_t         compare_value;
    uint64_t         swap_value;
} ses_header_t;

/* ═══════════════════════════════════════════════════════════════════
 *  MEMORY REGION KEY FORMAT  (Table 2-13)
 * ═══════════════════════════════════════════════════════════════════ */
#define MR_KEY_IDEMPOTENT_SAFE   (1ULL << 63)
#define MR_KEY_OPTIMIZED         (1ULL << 62)
#define MR_KEY_RKEY_MASK         0x0000FFFFFFFFFFFFULL  /* bits 0:47 */
#define MR_KEY_INDEX_MASK        0x0000000000000FFFULL  /* bits 0:11 (optimised) */

/* ═══════════════════════════════════════════════════════════════════
 *  JOB-ID METHODS  (section 2.2.4)
 * ═══════════════════════════════════════════════════════════════════ */
typedef enum {
    JOBID_INDIRECT = 0,   /* auth_key_size = 0 (default) */
    JOBID_DIRECT   = 3,   /* auth_key_size = 3           */
    JOBID_AV       = 255, /* auth_key_size = FI_AV_AUTH_KEY */
} jobid_method_t;

#define UET_FALLBACK_JOBID  16777215u

/* ═══════════════════════════════════════════════════════════════════
 *  SECURITY BINDING PARAMETERS  (Table 2-33)
 * ═══════════════════════════════════════════════════════════════════ */
#define UET_SEC_ALG_AES_GCM_256      0
#define UET_SEC_REKEY_MODE_AN        (1 << 0)
#define UET_SEC_REKEY_MODE_AUTO      (1 << 1)
#define UET_SEC_CRYPTO_MODE_DIRECT   0
#define UET_SEC_CRYPTO_MODE_CLUSTER  1
#define UET_SEC_CRYPTO_MODE_CSERVER  2
#define UET_SEC_MAX_KEY_OCTETS       64

typedef struct {
    uint8_t  alg;          /* cipher algorithm                        */
    uint8_t  rekey;        /* rekey mode                              */
    uint8_t  crypto_mode;  /* direct / cluster / client-server        */
    uint8_t  rekey_shift;  /* shift for automatic rekeying            */
    uint64_t rekey_mask;   /* mask for automatic rekeying             */
    uint16_t coff;         /* crypto offset (units of 4B)             */
    uint16_t aoff;         /* authentication offset                   */
    uint32_t an_sdi;       /* AN(1 bit) | SDI(31 bits)                */
    uint32_t ssi;          /* secure source identifier                */
    uint8_t  encap_type;   /* 0=native-IPv4 .. 3=UDP-IPv6             */
} uet_sec_bindings_t;

/* ═══════════════════════════════════════════════════════════════════
 *  SIMULATED ENDPOINT CONTEXT
 * ═══════════════════════════════════════════════════════════════════ */
#define MAX_MR          64
#define MAX_RECV_BUFS   256
#define MAX_JOBIDS      16
#define MAX_AV_ENTRIES  1024

typedef struct {
    void        *buf;
    size_t       len;
    uint64_t     job_id;    /* 0 = any JobID */
    uint64_t     tag;
    uint64_t     ignore;    /* tag mask for wildcard */
    fi_addr_t    src_addr;  /* FI_ADDR_UNSPEC = any */
    bool         tagged;
    bool         consumed;
    uint64_t     flags;
} sim_recv_buf_t;

typedef struct {
    uint64_t         key;       /* full 64-bit MR key */
    void            *buf;
    size_t           len;
    uint64_t         access;
    uint64_t         job_id;    /* 0 = any JobID */
    bool             valid;
    bool             cntr_bound;
} sim_mr_t;

/* Simulated completion queue entry */
typedef struct {
    uint64_t  op_context;
    uint64_t  flags;
    size_t    len;
    uint64_t  data;   /* remote CQ data */
    uint64_t  tag;
    int       err;    /* 0 = success */
    int       prov_errno;
} sim_cq_entry_t;

/* Simulated completion counter */
typedef struct {
    uint64_t        count;       /* completed operations  */
    uint64_t        byte_count;  /* completed bytes       */
    pthread_mutex_t lock;
} sim_cntr_t;

/* Per-endpoint simulation state */
typedef struct {
    /* Profile and addressing */
    uet_profile_t    profile;
    struct uet_addr  local_addr;
    uint32_t         job_id;         /* primary JobID      */
    jobid_method_t   jobid_method;
    bool             absolute_addr;

    /* Endpoint type */
    enum fi_ep_type  ep_type;        /* FI_EP_DGRAM / FI_EP_RDM */

    /* Receive queues (independent for untagged / tagged) */
    sim_recv_buf_t   untagged_rq[MAX_RECV_BUFS];
    int              untagged_rq_head, untagged_rq_tail;
    sim_recv_buf_t   tagged_rq[MAX_RECV_BUFS];
    int              tagged_rq_head,   tagged_rq_tail;

    /* Memory regions */
    sim_mr_t         mrs[MAX_MR];
    int              mr_count;

    /* Address Vector */
    struct uet_addr  av_table[MAX_AV_ENTRIES];
    uint32_t         av_jobids[MAX_AV_ENTRIES];  /* AV JobID method */
    int              av_count;

    /* Message ordering */
    bool             send_ordering;  /* any FI_ORDER_*AS* mode */
    bool             rw_ordering;    /* any R/W ordering mode  */

    /* Packet delivery mode selection */
    uet_pdm_t       (*select_pdm)(void *ep, ses_opcode_t op);

    /* Completion */
    sim_cq_entry_t   cq_ring[MAX_RECV_BUFS];
    int              cq_head, cq_tail;
    sim_cntr_t       tx_cntr, rx_cntr, read_cntr, write_cntr,
                     remote_read_cntr, remote_write_cntr;

    /* Security */
    uet_sec_bindings_t sec;
    bool               sec_enabled;

    /* Provider configuration */
    uint32_t   msg_rendezvous_size;
    uint32_t   tag_rendezvous_size;
    uint32_t   max_eager_size;

    /* Statistics */
    uint64_t   stat_sends, stat_tagged_sends, stat_rma_reads,
               stat_rma_writes, stat_atomics, stat_rendezvous,
               stat_deferrable;

    pthread_mutex_t lock;
} sim_ep_ctx_t;

/* ═══════════════════════════════════════════════════════════════════
 *  FUNCTION DECLARATIONS
 * ═══════════════════════════════════════════════════════════════════ */

/* Initialisation */
int  uet_sim_init(sim_ep_ctx_t *ep, uet_profile_t profile,
                  enum fi_ep_type ep_type, uint32_t ipv4, uint32_t job_id,
                  uint32_t initiator_id, jobid_method_t jobid_method);

/* Internal: resolve JobID for SES header (used across translation units) */
uint32_t resolve_ses_jobid(sim_ep_ctx_t *ep, fi_addr_t dest_av_idx);
void uet_sim_destroy(sim_ep_ctx_t *ep);

/* Profile negotiation (section 2.2.2.1) */
uet_profile_t uet_negotiate_profile(sim_ep_ctx_t *src, sim_ep_ctx_t *dst);

/* JobID management */
int  uet_assign_jobid(sim_ep_ctx_t *ep, uint32_t job_id);
int  uet_fallback_jobid(sim_ep_ctx_t *ep, uint32_t initiator_id);
int  uet_av_insert_jobid(sim_ep_ctx_t *ep, fi_addr_t addr, uint32_t job_id);

/* Authorization */
bool uet_authorize_recv_buf(sim_ep_ctx_t *ep, sim_recv_buf_t *buf,
                             uint32_t ses_job_id);
bool uet_authorize_mr(sim_ep_ctx_t *ep, sim_mr_t *mr, uint32_t ses_job_id);

/* PDM selection */
uet_pdm_t uet_select_pdm_ai_base(sim_ep_ctx_t *ep, ses_opcode_t op);
uet_pdm_t uet_select_pdm_ai_full(sim_ep_ctx_t *ep, ses_opcode_t op);
uet_pdm_t uet_select_pdm_hpc   (sim_ep_ctx_t *ep, ses_opcode_t op);

/* SES opcode selection */
ses_opcode_t uet_map_msg_send   (sim_ep_ctx_t *ep, size_t msg_len);
ses_opcode_t uet_map_tagged_send(sim_ep_ctx_t *ep, size_t msg_len);

/* SES header building */
void uet_build_ses_header(sim_ep_ctx_t *src, sim_ep_ctx_t *dst,
                          ses_opcode_t opcode, const void *buf, size_t len,
                          uint64_t tag, uint64_t rkey,
                          uint64_t remote_cq_data, bool has_cq_data,
                          ses_header_t *hdr);
ses_hdr_format_t uet_choose_hdr_format(ses_opcode_t opcode, size_t len,
                                        uint64_t mr_key, bool has_cq_data,
                                        uint32_t mtu, bool opt_supported);

/* fi_msg() simulation */
int uet_sim_fi_send   (sim_ep_ctx_t *src, sim_ep_ctx_t *dst,
                       const void *buf, size_t len, uint64_t flags,
                       uint64_t op_ctx);
int uet_sim_fi_recv   (sim_ep_ctx_t *ep, void *buf, size_t len,
                       uint64_t flags, fi_addr_t src_addr);
int uet_sim_fi_senddata(sim_ep_ctx_t *src, sim_ep_ctx_t *dst,
                        const void *buf, size_t len,
                        uint64_t data, uint64_t op_ctx);
int uet_sim_fi_inject  (sim_ep_ctx_t *src, sim_ep_ctx_t *dst,
                        const void *buf, size_t len);

/* fi_tagged() simulation */
int uet_sim_fi_tsend  (sim_ep_ctx_t *src, sim_ep_ctx_t *dst,
                       const void *buf, size_t len,
                       uint64_t tag, uint64_t flags, uint64_t op_ctx);
int uet_sim_fi_trecv  (sim_ep_ctx_t *ep, void *buf, size_t len,
                       uint64_t tag, uint64_t ignore,
                       fi_addr_t src_addr, uint64_t flags);

/* fi_rma() simulation */
int uet_sim_fi_write  (sim_ep_ctx_t *src, sim_ep_ctx_t *dst,
                       const void *buf, size_t len,
                       uint64_t remote_addr, uint64_t rkey, uint64_t flags);
int uet_sim_fi_read   (sim_ep_ctx_t *src, sim_ep_ctx_t *dst,
                       void *buf, size_t len,
                       uint64_t remote_addr, uint64_t rkey, uint64_t flags);

/* fi_atomic() simulation */
int uet_sim_fi_atomic (sim_ep_ctx_t *src, sim_ep_ctx_t *dst,
                       const void *buf, size_t count,
                       uint64_t remote_addr, uint64_t rkey,
                       enum fi_datatype dt, enum fi_op op,
                       uint64_t flags);
int uet_sim_fi_fetch_atomic(sim_ep_ctx_t *src, sim_ep_ctx_t *dst,
                            const void *buf, size_t count,
                            void *result,
                            uint64_t remote_addr, uint64_t rkey,
                            enum fi_datatype dt, enum fi_op op,
                            uint64_t flags);

/* Memory region */
int  uet_sim_mr_reg(sim_ep_ctx_t *ep, void *buf, size_t len,
                    uint64_t access, uint64_t requested_key,
                    uint64_t job_id, int *mr_idx);
int  uet_sim_mr_lookup(sim_ep_ctx_t *ep, uint64_t rkey, sim_mr_t **mr);

/* Completion */
int  uet_sim_cq_read (sim_ep_ctx_t *ep, sim_cq_entry_t *entry);
void uet_sim_cq_write(sim_ep_ctx_t *ep, uint64_t op_ctx, uint64_t flags,
                      size_t len, uint64_t data, uint64_t tag, int err);
void uet_sim_cntr_inc(sim_cntr_t *cntr, size_t bytes);

/* Rendezvous helpers */
int  uet_sim_rendezvous_send(sim_ep_ctx_t *src, sim_ep_ctx_t *dst,
                              const void *buf, size_t len,
                              uint64_t tag, bool tagged, uint64_t flags);
int  uet_sim_deferrable_send(sim_ep_ctx_t *src, sim_ep_ctx_t *dst,
                              const void *buf, size_t len,
                              uint64_t tag, bool tagged, uint64_t flags);

/* Security */
int  uet_sim_sec_init(sim_ep_ctx_t *ep, const uet_sec_bindings_t *sec);

/* Diagnostic helpers */
void uet_dump_addr  (const struct uet_addr *a);
void uet_dump_ses_hdr(const ses_header_t *h);
void uet_dump_stats (sim_ep_ctx_t *ep);
void uet_dump_mr_key(uint64_t key);

#endif /* UET_SIM_H */