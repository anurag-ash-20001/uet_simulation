/*
 * uet_sim_core.c
 * Core simulation engine: addressing, JobID, authorization,
 * PDM selection, SES header building, MR management, CQ/cntr.
 */

#include "uet_sim.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <arpa/inet.h>
#include <unistd.h>

#define LOG(fmt,...) fprintf(stderr,"[UET] " fmt "\n",##__VA_ARGS__)
#define UET_MTU      4096u          /* simulated MTU in bytes */

/* ───────────────────────────────────────────────────────────────────
 * INIT / DESTROY
 * ─────────────────────────────────────────────────────────────────── */
int uet_sim_init(sim_ep_ctx_t *ep, uet_profile_t profile,
                 enum fi_ep_type ep_type, uint32_t ipv4,
                 uint32_t job_id, uint32_t initiator_id,
                 jobid_method_t jobid_method)
{
    memset(ep, 0, sizeof(*ep));
    pthread_mutex_init(&ep->lock, NULL);
    pthread_mutex_init(&ep->tx_cntr.lock, NULL);
    pthread_mutex_init(&ep->rx_cntr.lock, NULL);
    pthread_mutex_init(&ep->read_cntr.lock, NULL);
    pthread_mutex_init(&ep->write_cntr.lock, NULL);
    pthread_mutex_init(&ep->remote_read_cntr.lock, NULL);
    pthread_mutex_init(&ep->remote_write_cntr.lock, NULL);

    ep->profile       = profile;
    ep->ep_type       = ep_type;
    ep->jobid_method  = jobid_method;
    ep->job_id        = job_id;
    ep->absolute_addr = true;   /* default: absolute addressing */

    /* Build UET address (Table 2-10) */
    ep->local_addr.ver           = 0;
    ep->local_addr.flags         = UET_ADDR_FLAG_FA_V | UET_ADDR_FLAG_INI_V
                                 | UET_ADDR_FLAG_ABS_MODE | UET_ADDR_FLAG_IPV4
                                 | UET_ADDR_FLAG_FEP_CAP_V;
    ep->local_addr.fa.v4         = htonl(ipv4);
    ep->local_addr.initiator_id  = initiator_id;
    ep->local_addr.pid_on_fep    = (uint16_t)(getpid() & 0xFFFF);
    ep->local_addr.flags        |= UET_ADDR_FLAG_PID_V;

    /* Announce profile capability bits */
    ep->local_addr.fep_cap = (1 << profile);   /* profile and all lower */
    if (profile >= UET_PROFILE_AI_FULL)
        ep->local_addr.fep_cap |= UET_ADDR_FEP_AI_BASE;
    if (profile >= UET_PROFILE_HPC)
        ep->local_addr.fep_cap |= UET_ADDR_FEP_AI_FULL;

    /* Default provider rendezvous thresholds */
    ep->msg_rendezvous_size = 65536u;
    ep->tag_rendezvous_size = 65536u;
    ep->max_eager_size      = 4096u;

    /* Assign PDM selector */
    switch (profile) {
    case UET_PROFILE_AI_BASE:
        ep->select_pdm = (uet_pdm_t(*)(void*,ses_opcode_t))
                          uet_select_pdm_ai_base; break;
    case UET_PROFILE_AI_FULL:
        ep->select_pdm = (uet_pdm_t(*)(void*,ses_opcode_t))
                          uet_select_pdm_ai_full; break;
    default:
        ep->select_pdm = (uet_pdm_t(*)(void*,ses_opcode_t))
                          uet_select_pdm_hpc;     break;
    }

    LOG("Endpoint initialised: profile=%s ep_type=%s IPv4=%u.%u.%u.%u "
        "JobID=%u InitID=%u",
        uet_profile_str[profile],
        ep_type == FI_EP_DGRAM ? "FI_EP_DGRAM" : "FI_EP_RDM",
        (ipv4>>24)&0xFF,(ipv4>>16)&0xFF,(ipv4>>8)&0xFF, ipv4&0xFF,
        job_id, initiator_id);
    return 0;
}

void uet_sim_destroy(sim_ep_ctx_t *ep)
{
    pthread_mutex_destroy(&ep->lock);
    pthread_mutex_destroy(&ep->tx_cntr.lock);
    pthread_mutex_destroy(&ep->rx_cntr.lock);
    pthread_mutex_destroy(&ep->read_cntr.lock);
    pthread_mutex_destroy(&ep->write_cntr.lock);
    pthread_mutex_destroy(&ep->remote_read_cntr.lock);
    pthread_mutex_destroy(&ep->remote_write_cntr.lock);
    LOG("Endpoint destroyed. stats: sends=%lu tagged=%lu rma_r=%lu "
        "rma_w=%lu atoms=%lu rdv=%lu def=%lu",
        ep->stat_sends, ep->stat_tagged_sends, ep->stat_rma_reads,
        ep->stat_rma_writes, ep->stat_atomics,
        ep->stat_rendezvous, ep->stat_deferrable);
}

/* ───────────────────────────────────────────────────────────────────
 * PROFILE NEGOTIATION  (section 2.2.2.1, Table 2-6)
 * ─────────────────────────────────────────────────────────────────── */
uet_profile_t uet_negotiate_profile(sim_ep_ctx_t *src, sim_ep_ctx_t *dst)
{
    uint16_t common = src->local_addr.fep_cap & dst->local_addr.fep_cap;
    uet_profile_t best = UET_PROFILE_AI_BASE;

    /* Highest-priority common profile wins */
    if (common & UET_ADDR_FEP_HPC)       best = UET_PROFILE_HPC;
    else if (common & UET_ADDR_FEP_AI_FULL) best = UET_PROFILE_AI_FULL;
    else if (common & UET_ADDR_FEP_AI_BASE) best = UET_PROFILE_AI_BASE;

    /* AI Full <-> HPC interoperability (section 2.2.3, p.73):
       operations limited to AI Full; HPC treats deferrable as send */
    if ((src->profile == UET_PROFILE_AI_FULL && dst->profile == UET_PROFILE_HPC) ||
        (src->profile == UET_PROFILE_HPC    && dst->profile == UET_PROFILE_AI_FULL))
        best = UET_PROFILE_AI_FULL;   /* restrict to AI Full capability set */

    LOG("Profile negotiation: src=%s dst=%s → using %s",
        uet_profile_str[src->profile], uet_profile_str[dst->profile],
        uet_profile_str[best]);
    return best;
}

/* ───────────────────────────────────────────────────────────────────
 * JOB-ID MANAGEMENT  (section 2.2.4)
 * ─────────────────────────────────────────────────────────────────── */
int uet_assign_jobid(sim_ep_ctx_t *ep, uint32_t job_id)
{
    /* Simulates privileged entity assigning a JobID (section 2.2.4.1).
       In a real implementation the kernel driver validates this. */
    ep->job_id = job_id;
    LOG("JobID assigned: %u (method=%s)",
        job_id,
        ep->jobid_method==JOBID_INDIRECT?"Indirect":
        ep->jobid_method==JOBID_DIRECT  ?"Direct"  :"AV");
    return 0;
}

int uet_fallback_jobid(sim_ep_ctx_t *ep, uint32_t initiator_id)
{
    /* section 2.2.4.2 */
    ep->job_id = UET_FALLBACK_JOBID;
    ep->local_addr.initiator_id = initiator_id;
    LOG("Fallback JobID assigned: %u, InitiatorID=%u",
        UET_FALLBACK_JOBID, initiator_id);
    return 0;
}

int uet_av_insert_jobid(sim_ep_ctx_t *ep, fi_addr_t av_idx, uint32_t job_id)
{
    /* fi_av_insert_auth_key() simulation */
    if (av_idx >= MAX_AV_ENTRIES) return -FI_EINVAL;
    ep->av_jobids[av_idx] = job_id;
    LOG("AV JobID inserted: av_idx=%lu job_id=%u", av_idx, job_id);
    return 0;
}

/* Resolve the JobID that should go into ses.JobID for a given operation */
uint32_t resolve_ses_jobid(sim_ep_ctx_t *ep, fi_addr_t dest_av_idx)
{
    switch (ep->jobid_method) {
    case JOBID_INDIRECT:
        return ep->job_id;       /* provider supplies it */
    case JOBID_DIRECT:
        return ep->job_id;       /* auth_key attribute   */
    case JOBID_AV:
        if (dest_av_idx < (fi_addr_t)ep->av_count)
            return ep->av_jobids[dest_av_idx];
        return ep->job_id;
    default:
        return ep->job_id;
    }
}

/* ───────────────────────────────────────────────────────────────────
 * AUTHORIZATION  (section 2.2.4.3)
 * ─────────────────────────────────────────────────────────────────── */
bool uet_authorize_recv_buf(sim_ep_ctx_t *ep, sim_recv_buf_t *buf,
                             uint32_t ses_job_id)
{
    /* Only in absolute addressing mode (section 2.2.4.3 preamble) */
    if (!ep->absolute_addr) return true;

    if (buf->job_id == 0)           return true;   /* "any" JobID */
    if (buf->job_id == ses_job_id)  return true;
    LOG("WARN: recv buffer auth FAILED: buf_jid=%lu ses_jid=%u",
        buf->job_id, ses_job_id);
    return false;
}

bool uet_authorize_mr(sim_ep_ctx_t *ep, sim_mr_t *mr, uint32_t ses_job_id)
{
    if (!ep->absolute_addr) return true;
    if (mr->job_id == 0)           return true;
    if (mr->job_id == ses_job_id)  return true;
    LOG("WARN: MR auth FAILED: mr_jid=%lu ses_jid=%u",
        mr->job_id, ses_job_id);
    return false;
}

/* ───────────────────────────────────────────────────────────────────
 * PACKET DELIVERY MODE SELECTION  (section 2.2.6, Tables 2-29..2-31)
 * ─────────────────────────────────────────────────────────────────── */
uet_pdm_t uet_select_pdm_ai_base(sim_ep_ctx_t *ep, ses_opcode_t op)
{
    bool is_rma_or_atomic = (op == SES_OP_READ  || op == SES_OP_WRITE ||
                              op == SES_OP_ATOMIC || op == SES_OP_FETCHING_ATOMIC);
    bool is_send = !is_rma_or_atomic;

    /* Table 2-29 */
    if (!ep->send_ordering && !ep->rw_ordering) return PDM_RUD;
    if (!ep->send_ordering &&  ep->rw_ordering)
        return is_send ? PDM_RUD : PDM_ROD;
    if ( ep->send_ordering && !ep->rw_ordering)
        return is_send ? PDM_ROD : PDM_RUD;
    return PDM_ROD;  /* both orderings: ROD */
}

uet_pdm_t uet_select_pdm_ai_full(sim_ep_ctx_t *ep, ses_opcode_t op)
{
    /* Table 2-30 */
    bool is_def  = (op == SES_OP_DEFERRABLE_SEND ||
                    op == SES_OP_DEFERRABLE_TSEND);
    bool is_rma  = (op == SES_OP_READ || op == SES_OP_WRITE ||
                    op == SES_OP_ATOMIC || op == SES_OP_FETCHING_ATOMIC);

    if (!ep->send_ordering && !ep->rw_ordering) return PDM_RUD;
    if (!ep->send_ordering &&  ep->rw_ordering)
        return (is_rma) ? PDM_ROD : PDM_RUD;
    if ( ep->send_ordering && !ep->rw_ordering) {
        if (is_def) { /* initial/eager→ROD, remaining→RUD; report ROD */
            LOG("  Deferrable send: initial/eager=ROD, remaining=RUD");
            return PDM_ROD;
        }
        return is_rma ? PDM_RUD : PDM_ROD;
    }
    /* send && rw ordering */
    if (is_def) { LOG("  Deferrable send: initial/eager=ROD, remaining=RUD"); }
    return PDM_ROD;
}

uet_pdm_t uet_select_pdm_hpc(sim_ep_ctx_t *ep, ses_opcode_t op)
{
    /* Table 2-31 */
    bool is_rdv   = (op == SES_OP_RENDEZVOUS_SEND  ||
                     op == SES_OP_RENDEZVOUS_TSEND);
    bool is_rma   = (op == SES_OP_READ || op == SES_OP_WRITE);
    bool is_atomic= (op == SES_OP_ATOMIC || op == SES_OP_FETCHING_ATOMIC);

    if (!ep->send_ordering && !ep->rw_ordering) {
        if (is_rma) return PDM_RUDI;   /* vendor policy: prefer RUDI */
        return PDM_RUD;
    }
    if (!ep->send_ordering && ep->rw_ordering) {
        if (is_rma || is_atomic) return PDM_ROD;
        return PDM_RUD;
    }
    if (ep->send_ordering && !ep->rw_ordering) {
        if (is_rdv)  { LOG("  Rendezvous: initial/eager=ROD, remaining=RUD"); }
        if (is_rma)  return PDM_RUDI;
        if (is_atomic) return PDM_RUD;
        return PDM_ROD;
    }
    /* both orderings */
    if (is_rdv)    { LOG("  Rendezvous: initial/eager=ROD, remaining=RUD"); }
    if (is_rma || is_atomic) return PDM_ROD;
    return PDM_ROD;
}

/* ───────────────────────────────────────────────────────────────────
 * SES OPCODE SELECTION  (Tables 2-22, 2-24)
 * ─────────────────────────────────────────────────────────────────── */
ses_opcode_t uet_map_msg_send(sim_ep_ctx_t *ep, size_t msg_len)
{
    if (ep->ep_type == FI_EP_DGRAM)
        return SES_OP_DATAGRAM_SEND;

    /* FI_EP_RDM */
    if (ep->profile == UET_PROFILE_AI_FULL) {
        if (msg_len >= ep->msg_rendezvous_size)
            return SES_OP_DEFERRABLE_SEND;
        return SES_OP_SEND;
    }
    if (ep->profile == UET_PROFILE_HPC) {
        /* rendezvous if size threshold met (source buffer must be registered;
           assume so for simulation) */
        if (msg_len >= ep->msg_rendezvous_size)
            return SES_OP_RENDEZVOUS_SEND;
        return SES_OP_SEND;
    }
    return SES_OP_SEND;  /* AI Base */
}

ses_opcode_t uet_map_tagged_send(sim_ep_ctx_t *ep, size_t msg_len)
{
    if (ep->profile == UET_PROFILE_AI_FULL) {
        if (msg_len >= ep->tag_rendezvous_size)
            return SES_OP_DEFERRABLE_TSEND;
        return SES_OP_TAGGED_SEND;
    }
    if (ep->profile == UET_PROFILE_HPC) {
        if (msg_len >= ep->tag_rendezvous_size)
            return SES_OP_RENDEZVOUS_TSEND;
        return SES_OP_TAGGED_SEND;
    }
    return SES_OP_TAGGED_SEND;
}

/* ───────────────────────────────────────────────────────────────────
 * SES HEADER FORMAT CHOICE  (section 2.2.5.3.4.1, Tables 2-14/15/41)
 * ─────────────────────────────────────────────────────────────────── */
ses_hdr_format_t uet_choose_hdr_format(ses_opcode_t opcode, size_t len,
                                        uint64_t mr_key, bool has_cq_data,
                                        uint32_t mtu, bool opt_supported)
{
    bool is_rma_or_atomic = (opcode == SES_OP_READ  || opcode == SES_OP_WRITE ||
                              opcode == SES_OP_ATOMIC || opcode == SES_OP_FETCHING_ATOMIC);
    bool is_tagged = (opcode == SES_OP_TAGGED_SEND    ||
                      opcode == SES_OP_DEFERRABLE_TSEND ||
                      opcode == SES_OP_RENDEZVOUS_TSEND);

    /* Table 2-41: small message */
    if (is_tagged && len <= mtu && !has_cq_data)
        return SES_HDR_SMALL_MSG;

    /* Table 2-14: optimised non-matching for RMA/atomic */
    if (is_rma_or_atomic && !has_cq_data && len <= mtu && opt_supported &&
        (mr_key & MR_KEY_OPTIMIZED))
        return SES_HDR_NON_MATCHING;

    /* Table 2-15: small RMA */
    if (is_rma_or_atomic && !has_cq_data && len <= mtu)
        return SES_HDR_SMALL_MSG;

    if (opcode == SES_OP_DEFERRABLE_SEND || opcode == SES_OP_DEFERRABLE_TSEND)
        return SES_HDR_DEFERRABLE_SEND;

    if (opcode == SES_OP_RENDEZVOUS_SEND || opcode == SES_OP_RENDEZVOUS_TSEND)
        return SES_HDR_RENDEZVOUS_EXT;

    if (opcode == SES_OP_ATOMIC || opcode == SES_OP_TSEND_ATOMIC)
        return SES_HDR_ATOMIC_EXT;

    if (opcode == SES_OP_FETCHING_ATOMIC)
        return SES_HDR_ATOMIC_EXT;

    return SES_HDR_STANDARD;
}

/* ───────────────────────────────────────────────────────────────────
 * SES HEADER BUILDER  (Table 2-39 .. 2-44)
 * ─────────────────────────────────────────────────────────────────── */
void uet_build_ses_header(sim_ep_ctx_t *src, sim_ep_ctx_t *dst,
                          ses_opcode_t opcode,
                          const void *buf, size_t len,
                          uint64_t tag, uint64_t rkey,
                          uint64_t remote_cq_data, bool has_cq_data,
                          ses_header_t *hdr)
{
    bool opt_supp = !!(dst->local_addr.fep_cap & UET_ADDR_FEP_OPT_NM_SEM);

    memset(hdr, 0, sizeof(*hdr));
    hdr->format  = uet_choose_hdr_format(opcode, len, rkey, has_cq_data,
                                          UET_MTU, opt_supp);
    hdr->opcode  = opcode;

    /* Common fields */
    hdr->job_id        = resolve_ses_jobid(src, 0);
    hdr->pid_on_fep    = dst->local_addr.pid_on_fep;
    hdr->resource_index= dst->local_addr.start_resource_idx;
    hdr->initiator     = src->local_addr.initiator_id;
    hdr->request_length= (uint32_t)len;
    hdr->relative      = !dst->absolute_addr;
    hdr->header_data_present = has_cq_data;
    if (has_cq_data) hdr->header_data = remote_cq_data;

    /* opcode-specific */
    switch (opcode) {
    case SES_OP_TAGGED_SEND:
    case SES_OP_DEFERRABLE_TSEND:
    case SES_OP_RENDEZVOUS_TSEND:
        hdr->match_bits = tag;
        break;
    case SES_OP_READ:
    case SES_OP_WRITE:
    case SES_OP_ATOMIC:
    case SES_OP_FETCHING_ATOMIC:
    case SES_OP_TSEND_ATOMIC:
        hdr->match_bits = rkey;
        break;
    default: break;
    }

    /* Rendezvous extension (Table 2-44) */
    if (hdr->format == SES_HDR_RENDEZVOUS_EXT) {
        hdr->eager_length      = (len > src->max_eager_size)
                                   ? src->max_eager_size : (uint32_t)len;
        hdr->read_pid_on_fep   = src->local_addr.pid_on_fep;
        hdr->read_resource_index = src->local_addr.start_resource_idx;
        hdr->read_memory_key   = rkey;
        hdr->read_offset       = 0;   /* start of MR */
    }

    /* Deferrable send tokens */
    if (hdr->format == SES_HDR_DEFERRABLE_SEND) {
        static uint32_t tok = 1;
        hdr->initiator_restart_token = tok++;
        hdr->target_restart_token    = tok++;
    }
}

/* ───────────────────────────────────────────────────────────────────
 * MEMORY REGION MANAGEMENT  (section 2.2.5.3.4)
 * ─────────────────────────────────────────────────────────────────── */
int uet_sim_mr_reg(sim_ep_ctx_t *ep, void *buf, size_t len,
                   uint64_t access, uint64_t requested_key,
                   uint64_t job_id, int *mr_idx)
{
    if (ep->mr_count >= MAX_MR) return -FI_ENOMEM;

    sim_mr_t *mr = &ep->mrs[ep->mr_count];
    mr->buf      = buf;
    mr->len      = len;
    mr->access   = access;
    mr->job_id   = job_id;
    mr->valid    = true;
    mr->cntr_bound = false;

    /* Apply the standardised MR key format (Table 2-13) */
    uint64_t key = requested_key;
    /* Honour IDEMPOTENT_SAFE and OPTIMIZED from requested_key */
    /* For simulated provider-assigned RKEY (lower 48 bits = index) */
    key = (key & (MR_KEY_IDEMPOTENT_SAFE | MR_KEY_OPTIMIZED)) |
          ((uint64_t)ep->mr_count & MR_KEY_RKEY_MASK);

    /* If OPTIMIZED: RKEY/INDEX in bits 0:11 only */
    if (key & MR_KEY_OPTIMIZED)
        key = (key & ~MR_KEY_RKEY_MASK) |
              ((uint64_t)ep->mr_count & MR_KEY_INDEX_MASK);

    mr->key = key;
    if (mr_idx) *mr_idx = ep->mr_count;
    ep->mr_count++;

    LOG("MR registered: idx=%d buf=%p len=%zu key=0x%016lx job_id=%lu",
        ep->mr_count-1, buf, len, key, job_id);
    return 0;
}

int uet_sim_mr_lookup(sim_ep_ctx_t *ep, uint64_t rkey, sim_mr_t **mr)
{
    for (int i = 0; i < ep->mr_count; i++) {
        if (ep->mrs[i].valid && ep->mrs[i].key == rkey) {
            *mr = &ep->mrs[i];
            return 0;
        }
    }
    LOG("ERROR: MR lookup failed for rkey=0x%016lx", rkey);
    return -FI_ENOKEY;
}

/* ───────────────────────────────────────────────────────────────────
 * COMPLETION QUEUE / COUNTER  (section 2.2.5.3.7, Table 2-20)
 * ─────────────────────────────────────────────────────────────────── */
void uet_sim_cq_write(sim_ep_ctx_t *ep, uint64_t op_ctx, uint64_t flags,
                      size_t len, uint64_t data, uint64_t tag, int err)
{
    int next = (ep->cq_tail + 1) % MAX_RECV_BUFS;
    if (next == ep->cq_head) { LOG("WARN: CQ full, dropping entry"); return; }
    sim_cq_entry_t *e = &ep->cq_ring[ep->cq_tail];
    e->op_context = op_ctx;
    e->flags      = flags;
    e->len        = len;
    e->data       = data;
    e->tag        = tag;
    e->err        = err;
    e->prov_errno = err;   /* semantic error code, per spec */
    ep->cq_tail   = next;
}

int uet_sim_cq_read(sim_ep_ctx_t *ep, sim_cq_entry_t *entry)
{
    if (ep->cq_head == ep->cq_tail) return -FI_EAGAIN;
    *entry       = ep->cq_ring[ep->cq_head];
    ep->cq_head  = (ep->cq_head + 1) % MAX_RECV_BUFS;
    return 1;
}

void uet_sim_cntr_inc(sim_cntr_t *c, size_t bytes)
{
    pthread_mutex_lock(&c->lock);
    c->count++;
    c->byte_count += bytes;
    pthread_mutex_unlock(&c->lock);
}

/* ───────────────────────────────────────────────────────────────────
 * SECURITY INIT  (section 2.2.9)
 * ─────────────────────────────────────────────────────────────────── */
int uet_sim_sec_init(sim_ep_ctx_t *ep, const uet_sec_bindings_t *sec)
{
    ep->sec         = *sec;
    ep->sec_enabled = true;
    LOG("Security enabled: alg=%u mode=%u rekey=%u",
        sec->alg, sec->crypto_mode, sec->rekey);
    return 0;
}

/* ───────────────────────────────────────────────────────────────────
 * DIAGNOSTIC HELPERS
 * ─────────────────────────────────────────────────────────────────── */
void uet_dump_addr(const struct uet_addr *a)
{
    uint32_t ip = ntohl(a->fa.v4);
    printf("  UET Address v%u: %u.%u.%u.%u PIDonFEP=%u StartIdx=%u "
           "NumIdx=%u InitID=%u\n",
           a->ver,
           (ip>>24)&0xFF,(ip>>16)&0xFF,(ip>>8)&0xFF,ip&0xFF,
           a->pid_on_fep, a->start_resource_idx,
           a->num_resource_idx, a->initiator_id);
    printf("  Flags: FEP_CAP_V=%d FA_V=%d PID_V=%d RI_V=%d INI_V=%d "
           "ABS=%d IPV6=%d MTU=%d\n",
           !!(a->flags & UET_ADDR_FLAG_FEP_CAP_V),
           !!(a->flags & UET_ADDR_FLAG_FA_V),
           !!(a->flags & UET_ADDR_FLAG_PID_V),
           !!(a->flags & UET_ADDR_FLAG_RI_V),
           !!(a->flags & UET_ADDR_FLAG_INI_V),
           !!(a->flags & UET_ADDR_FLAG_ABS_MODE),
           !!(a->flags & UET_ADDR_FLAG_IPV6),
           !!(a->flags & UET_ADDR_FLAG_MTU_MSG_SIZE));
    printf("  FEP Caps: AI_BASE=%d AI_FULL=%d HPC=%d OPT_NM=%d\n",
           !!(a->fep_cap & UET_ADDR_FEP_AI_BASE),
           !!(a->fep_cap & UET_ADDR_FEP_AI_FULL),
           !!(a->fep_cap & UET_ADDR_FEP_HPC),
           !!(a->fep_cap & UET_ADDR_FEP_OPT_NM_SEM));
}

void uet_dump_ses_hdr(const ses_header_t *h)
{
    static const char *fmt_str[] = {
        "Standard","NonMatching","SmallMsg","DeferSend",
        "RTR","RendezvousExt","AtomicExt","CompareSwap","Response"
    };
    printf("  SES Header: fmt=%-14s op=%-22s len=%u jid=%u pid=%u "
           "ri=%u ini=%u\n",
           fmt_str[h->format], ses_op_str[h->opcode],
           h->request_length, h->job_id, h->pid_on_fep,
           h->resource_index, h->initiator);
    printf("              dc=%d rel=%d hd=%d match=0x%016lx",
           h->delivery_complete, h->relative,
           h->header_data_present, h->match_bits);
    if (h->format == SES_HDR_RENDEZVOUS_EXT)
        printf(" eager=%u rmk=0x%lx", h->eager_length, h->read_memory_key);
    if (h->format == SES_HDR_DEFERRABLE_SEND)
        printf(" itok=%u ttok=%u", h->initiator_restart_token,
               h->target_restart_token);
    printf("\n");
}

void uet_dump_mr_key(uint64_t key)
{
    printf("  MR Key 0x%016llx: IDEMPOTENT_SAFE=%d OPTIMIZED=%d RKEY=0x%012llx\n",
           (unsigned long long)key,
           !!(key & MR_KEY_IDEMPOTENT_SAFE),
           !!(key & MR_KEY_OPTIMIZED),
           (unsigned long long)(key & MR_KEY_RKEY_MASK));
}

void uet_dump_stats(sim_ep_ctx_t *ep)
{
    printf("  Stats: sends=%lu tagged=%lu rma_r=%lu rma_w=%lu "
           "atoms=%lu rdv=%lu def=%lu\n",
           ep->stat_sends, ep->stat_tagged_sends, ep->stat_rma_reads,
           ep->stat_rma_writes, ep->stat_atomics,
           ep->stat_rendezvous, ep->stat_deferrable);
    printf("  Cntrs: tx=%lu rx=%lu r=%lu w=%lu rr=%lu rw=%lu\n",
           ep->tx_cntr.count, ep->rx_cntr.count,
           ep->read_cntr.count, ep->write_cntr.count,
           ep->remote_read_cntr.count, ep->remote_write_cntr.count);
}