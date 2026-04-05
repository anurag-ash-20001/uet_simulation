/*
 * uet_sim_xfer.c
 * Data-transfer operations:
 *   fi_msg()    – section 2.2.5.4.1
 *   fi_tagged() – section 2.2.5.4.2
 *   fi_rma()    – section 2.2.5.4.3
 *   fi_atomic() – section 2.2.5.4.4
 * Rendezvous & deferrable-send protocols – section 2.2.5.4.1.2
 */

#include "uet_sim.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#define LOG(fmt,...) fprintf(stderr,"[UET-XFER] " fmt "\n",##__VA_ARGS__)

/* ── internal helpers ─────────────────────────────────────────────── */

/* Find first matching untagged receive buffer */
static sim_recv_buf_t *dequeue_untagged(sim_ep_ctx_t *ep,
                                         uint32_t ses_job_id)
{
    for (int i = ep->untagged_rq_head; i != ep->untagged_rq_tail;
         i = (i+1) % MAX_RECV_BUFS)
    {
        sim_recv_buf_t *b = &ep->untagged_rq[i];
        if (!b->consumed && !b->tagged &&
            uet_authorize_recv_buf(ep, b, ses_job_id))
        {
            b->consumed = true;
            return b;
        }
    }
    return NULL;
}

/* Find first matching tagged receive buffer (section 2.2.5.4.2.1) */
static sim_recv_buf_t *dequeue_tagged(sim_ep_ctx_t *ep,
                                       uint64_t tag,
                                       uint32_t ses_initiator,
                                       uint32_t ses_job_id)
{
    for (int i = ep->tagged_rq_head; i != ep->tagged_rq_tail;
         i = (i+1) % MAX_RECV_BUFS)
    {
        sim_recv_buf_t *b = &ep->tagged_rq[i];
        if (b->consumed || !b->tagged) continue;

        /* Tag matching: apply ignore mask */
        if ((tag & ~b->ignore) != (b->tag & ~b->ignore)) continue;

        /* src_addr matching (FI_ADDR_UNSPEC → skip initiator check) */
        if (b->src_addr != FI_ADDR_UNSPEC &&
            (uint32_t)b->src_addr != ses_initiator)
            continue;

        if (!uet_authorize_recv_buf(ep, b, ses_job_id)) continue;
        b->consumed = true;
        return b;
    }
    return NULL;
}

/* Enqueue a recv buffer */
static int enqueue_recv(sim_ep_ctx_t *ep, const sim_recv_buf_t *b)
{
    if (b->tagged) {
        int next = (ep->tagged_rq_tail+1) % MAX_RECV_BUFS;
        if (next == ep->tagged_rq_head) { LOG("Tagged RQ full"); return -FI_ENOMEM; }
        ep->tagged_rq[ep->tagged_rq_tail] = *b;
        ep->tagged_rq_tail = next;
    } else {
        int next = (ep->untagged_rq_tail+1) % MAX_RECV_BUFS;
        if (next == ep->untagged_rq_head) { LOG("Untagged RQ full"); return -FI_ENOMEM; }
        ep->untagged_rq[ep->untagged_rq_tail] = *b;
        ep->untagged_rq_tail = next;
    }
    return 0;
}

/* Generic "deliver" – copy data into matched receive buffer */
static int deliver_to_recv(sim_ep_ctx_t *dst, sim_recv_buf_t *rbuf,
                            const void *src_data, size_t len,
                            uint64_t cq_data, uint64_t tag,
                            uint64_t flags, int err)
{
    if (rbuf) {
        size_t copy_len = (len < rbuf->len) ? len : rbuf->len;
        memcpy(rbuf->buf, src_data, copy_len);
    }
    /* Write CQ entry at destination */
    uet_sim_cq_write(dst, 0 /*op_ctx*/, flags | FI_RECV,
                     len, cq_data, tag, err);
    uet_sim_cntr_inc(&dst->rx_cntr, len);
    return err;
}

/* ═══════════════════════════════════════════════════════════════════
 * fi_recv() / fi_recvv() / fi_recvmsg()  (Table 2-21)
 * ═══════════════════════════════════════════════════════════════════ */
int uet_sim_fi_recv(sim_ep_ctx_t *ep, void *buf, size_t len,
                    uint64_t flags, fi_addr_t src_addr)
{
    sim_recv_buf_t rb = {
        .buf      = buf, .len = len,
        .job_id   = 0,   /* section 2.2.4.3.1: indirect/direct → assigned jid */
        .tagged   = false, .consumed = false,
        .src_addr = src_addr, .flags = flags
    };
    if (ep->jobid_method == JOBID_INDIRECT || ep->jobid_method == JOBID_DIRECT)
        rb.job_id = ep->job_id;

    LOG("fi_recv: ep=%p buf=%p len=%zu src_addr=%ld", ep, buf, len, src_addr);
    return enqueue_recv(ep, &rb);
}

/* ═══════════════════════════════════════════════════════════════════
 * fi_send() / fi_sendv() / fi_sendmsg()  (Table 2-22)
 * ═══════════════════════════════════════════════════════════════════ */
int uet_sim_fi_send(sim_ep_ctx_t *src, sim_ep_ctx_t *dst,
                    const void *buf, size_t len, uint64_t flags,
                    uint64_t op_ctx)
{
    uet_profile_t eff = uet_negotiate_profile(src, dst);
    ses_opcode_t  op  = uet_map_msg_send(src, len);
    uet_pdm_t     pdm = src->select_pdm(src, op);

    /* Rendezvous path */
    if (op == SES_OP_RENDEZVOUS_SEND)
        return uet_sim_rendezvous_send(src, dst, buf, len, 0, false, flags);
    if (op == SES_OP_DEFERRABLE_SEND)
        return uet_sim_deferrable_send(src, dst, buf, len, 0, false, flags);

    ses_header_t hdr;
    uet_build_ses_header(src, dst, op, buf, len, 0, 0, 0, false, &hdr);

    LOG("fi_send: len=%zu op=%s pdm=%s profile=%s",
        len, ses_op_str[op], pdm_str[pdm], uet_profile_str[eff]);
    uet_dump_ses_hdr(&hdr);

    /* Deliver */
    uint32_t ses_jid = hdr.job_id;
    sim_recv_buf_t *rbuf = dequeue_untagged(dst, ses_jid);
    if (!rbuf) {
        /* Unexpected message – per spec, provider handles via SES mechanism */
        LOG("WARN: No matching recv buffer (unexpected message), buffering");
        /* For simulation: write error CQ at source */
        uet_sim_cq_write(src, op_ctx, FI_SEND, len, 0, 0, 0);
        uet_sim_cntr_inc(&src->tx_cntr, len);
        src->stat_sends++;
        return 0;  /* still succeeds; target handles buffer asynchronously */
    }

    deliver_to_recv(dst, rbuf, buf, len, 0, 0, flags, 0);
    uet_sim_cq_write(src, op_ctx, FI_SEND, len, 0, 0, 0);
    uet_sim_cntr_inc(&src->tx_cntr, len);
    src->stat_sends++;
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════
 * fi_senddata()  (Table 2-22)  – remote CQ data in ses.header_data
 * ═══════════════════════════════════════════════════════════════════ */
int uet_sim_fi_senddata(sim_ep_ctx_t *src, sim_ep_ctx_t *dst,
                        const void *buf, size_t len,
                        uint64_t data, uint64_t op_ctx)
{
    ses_opcode_t op  = uet_map_msg_send(src, len);
    uet_pdm_t    pdm = src->select_pdm(src, op);
    ses_header_t hdr;
    uet_build_ses_header(src, dst, op, buf, len, 0, 0, data, true, &hdr);

    LOG("fi_senddata: len=%zu data=0x%lx op=%s pdm=%s",
        len, data, ses_op_str[op], pdm_str[pdm]);
    uet_dump_ses_hdr(&hdr);

    uint32_t ses_jid = hdr.job_id;
    sim_recv_buf_t *rbuf = dequeue_untagged(dst, ses_jid);
    deliver_to_recv(dst, rbuf, buf, len, data, 0, FI_REMOTE_CQ_DATA, 0);
    uet_sim_cq_write(src, op_ctx, FI_SEND, len, data, 0, 0);
    uet_sim_cntr_inc(&src->tx_cntr, len);
    src->stat_sends++;
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════
 * fi_inject()  (Table 2-22) – data immediately reusable, no CQ entry on success
 * ═══════════════════════════════════════════════════════════════════ */
int uet_sim_fi_inject(sim_ep_ctx_t *src, sim_ep_ctx_t *dst,
                      const void *buf, size_t len)
{
    ses_opcode_t op  = uet_map_msg_send(src, len);
    uet_pdm_t    pdm = src->select_pdm(src, op);
    ses_header_t hdr;
    uet_build_ses_header(src, dst, op, buf, len, 0, 0, 0, false, &hdr);

    LOG("fi_inject: len=%zu op=%s pdm=%s", len, ses_op_str[op], pdm_str[pdm]);

    uint32_t ses_jid = hdr.job_id;
    sim_recv_buf_t *rbuf = dequeue_untagged(dst, ses_jid);
    deliver_to_recv(dst, rbuf, buf, len, 0, 0, 0, 0);
    /* No CQ entry for inject on success; only on error (FI_EP_RDM) */
    uet_sim_cntr_inc(&src->tx_cntr, len);
    src->stat_sends++;
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════
 * fi_trecv()  (Table 2-23)
 * ═══════════════════════════════════════════════════════════════════ */
int uet_sim_fi_trecv(sim_ep_ctx_t *ep, void *buf, size_t len,
                     uint64_t tag, uint64_t ignore,
                     fi_addr_t src_addr, uint64_t flags)
{
    /* AI Full: only exact match; ignore bits MUST be 0 (or fail) */
    if (ep->profile == UET_PROFILE_AI_FULL && ignore != 0) {
        LOG("fi_trecv: AI Full profile – wildcard tags not supported "
            "(ignore=0x%lx), failing", ignore);
        return -FI_EINVAL;
    }
    sim_recv_buf_t rb = {
        .buf      = buf,   .len    = len,
        .tag      = tag,   .ignore = ignore,
        .src_addr = src_addr, .tagged = true, .consumed = false,
        .job_id   = ep->job_id, .flags = flags
    };
    LOG("fi_trecv: tag=0x%016lx ignore=0x%016lx src=%ld",
        tag, ignore, src_addr);
    return enqueue_recv(ep, &rb);
}

/* ═══════════════════════════════════════════════════════════════════
 * fi_tsend()  (Table 2-24)
 * ═══════════════════════════════════════════════════════════════════ */
int uet_sim_fi_tsend(sim_ep_ctx_t *src, sim_ep_ctx_t *dst,
                     const void *buf, size_t len,
                     uint64_t tag, uint64_t flags, uint64_t op_ctx)
{
    /* Tagged APIs NOT supported for FI_EP_DGRAM */
    if (src->ep_type == FI_EP_DGRAM) {
        LOG("fi_tsend: tagged not supported on FI_EP_DGRAM"); return -FI_EINVAL;
    }

    uet_profile_t eff = uet_negotiate_profile(src, dst);
    ses_opcode_t  op  = uet_map_tagged_send(src, len);
    uet_pdm_t     pdm = src->select_pdm(src, op);

    if (op == SES_OP_RENDEZVOUS_TSEND)
        return uet_sim_rendezvous_send(src, dst, buf, len, tag, true, flags);
    if (op == SES_OP_DEFERRABLE_TSEND)
        return uet_sim_deferrable_send(src, dst, buf, len, tag, true, flags);

    ses_header_t hdr;
    bool has_cq = !!(flags & FI_REMOTE_CQ_DATA);
    uint64_t cq_data = has_cq ? flags : 0;  /* simplified for sim */
    uet_build_ses_header(src, dst, op, buf, len, tag, 0, cq_data, has_cq, &hdr);

    LOG("fi_tsend: len=%zu tag=0x%016lx op=%s pdm=%s profile=%s",
        len, tag, ses_op_str[op], pdm_str[pdm], uet_profile_str[eff]);
    uet_dump_ses_hdr(&hdr);

    uint32_t ses_jid = hdr.job_id;
    sim_recv_buf_t *rbuf = dequeue_tagged(dst, tag,
                                           src->local_addr.initiator_id,
                                           ses_jid);
    if (!rbuf) {
        LOG("WARN: No matching tagged recv (unexpected), buffering");
        uet_sim_cq_write(src, op_ctx, FI_TAGGED|FI_SEND, len, 0, tag, 0);
        uet_sim_cntr_inc(&src->tx_cntr, len);
        src->stat_tagged_sends++;
        return 0;
    }

    deliver_to_recv(dst, rbuf, buf, len, cq_data, tag,
                    FI_TAGGED | (has_cq ? FI_REMOTE_CQ_DATA : 0), 0);
    uet_sim_cq_write(src, op_ctx, FI_TAGGED|FI_SEND, len, 0, tag, 0);
    uet_sim_cntr_inc(&src->tx_cntr, len);
    src->stat_tagged_sends++;
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════
 * RENDEZVOUS SEND  (section 2.2.5.4.1.2)
 * ═══════════════════════════════════════════════════════════════════ */
int uet_sim_rendezvous_send(sim_ep_ctx_t *src, sim_ep_ctx_t *dst,
                             const void *buf, size_t len,
                             uint64_t tag, bool tagged, uint64_t flags)
{
    /* Find a local MR that covers 'buf' for remote-read access (sim: use key 0) */
    uint64_t rkey   = 0;  /* simplified: assume MR registered */
    ses_opcode_t op = tagged ? SES_OP_RENDEZVOUS_TSEND : SES_OP_RENDEZVOUS_SEND;
    ses_header_t hdr;
    uet_build_ses_header(src, dst, op, buf, len, tag, rkey, 0, false, &hdr);

    uint32_t eager_len = (len > src->max_eager_size) ?
                          src->max_eager_size : (uint32_t)len;
    LOG("RENDEZVOUS send: total=%zu eager=%u tag=0x%016lx op=%s",
        len, eager_len, tag, ses_op_str[op]);
    uet_dump_ses_hdr(&hdr);

    /* Phase 1: send RTS with eager portion */
    LOG("  Phase 1: RTS + %u eager bytes → dst", eager_len);

    /* Phase 2: dst sends CTS; src receives CTS (simulated) */
    LOG("  Phase 2: CTS from dst (buffer ready)");

    /* Phase 3: RMA READ pulls remaining data (simulated memcpy) */
    size_t remaining = (len > eager_len) ? len - eager_len : 0;
    if (remaining > 0)
        LOG("  Phase 3: RMA READ %zu remaining bytes from src", remaining);

    /* Deliver to destination */
    uint32_t ses_jid = hdr.job_id;
    sim_recv_buf_t *rbuf = tagged ?
        dequeue_tagged(dst, tag, src->local_addr.initiator_id, ses_jid) :
        dequeue_untagged(dst, ses_jid);
    deliver_to_recv(dst, rbuf, buf, len, 0, tag,
                    tagged ? FI_TAGGED : 0, 0);

    uet_sim_cq_write(src, 0, (tagged?FI_TAGGED:0)|FI_SEND, len, 0, tag, 0);
    uet_sim_cntr_inc(&src->tx_cntr, len);
    src->stat_rendezvous++;
    LOG("RENDEZVOUS send complete: %zu bytes", len);
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════
 * DEFERRABLE SEND  (section 2.2.5.4.1.2, AI Full profile)
 * ═══════════════════════════════════════════════════════════════════ */
int uet_sim_deferrable_send(sim_ep_ctx_t *src, sim_ep_ctx_t *dst,
                             const void *buf, size_t len,
                             uint64_t tag, bool tagged, uint64_t flags)
{
    ses_opcode_t op = tagged ? SES_OP_DEFERRABLE_TSEND : SES_OP_DEFERRABLE_SEND;
    ses_header_t hdr;
    uet_build_ses_header(src, dst, op, buf, len, tag, 0, 0, false, &hdr);

    LOG("DEFERRABLE send: total=%zu tag=0x%016lx itok=%u ttok=%u",
        len, tag, hdr.initiator_restart_token, hdr.target_restart_token);
    uet_dump_ses_hdr(&hdr);

    /* Phase 1: send request; dst may pause if no buffer available */
    LOG("  Phase 1: Deferrable send request → dst");

    /* Phase 2 (simulated): dst either accepts or sends RTR */
    bool dst_paused = false;  /* simulation: always accept immediately */
    if (dst_paused) {
        LOG("  Phase 2: dst paused – waiting for RTR (Ready To Restart)");
        LOG("  Phase 3: RTR received, restarting send");
    } else {
        LOG("  Phase 2: dst accepted immediately");
    }

    /* Deliver */
    uint32_t ses_jid = hdr.job_id;
    sim_recv_buf_t *rbuf = tagged ?
        dequeue_tagged(dst, tag, src->local_addr.initiator_id, ses_jid) :
        dequeue_untagged(dst, ses_jid);
    deliver_to_recv(dst, rbuf, buf, len, 0, tag,
                    tagged ? FI_TAGGED : 0, 0);

    uet_sim_cq_write(src, 0, (tagged?FI_TAGGED:0)|FI_SEND, len, 0, tag, 0);
    uet_sim_cntr_inc(&src->tx_cntr, len);
    src->stat_deferrable++;
    LOG("DEFERRABLE send complete: %zu bytes", len);
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════
 * fi_write()  (Table 2-25)  – SES opcode UET_WRITE
 * ═══════════════════════════════════════════════════════════════════ */
int uet_sim_fi_write(sim_ep_ctx_t *src, sim_ep_ctx_t *dst,
                     const void *buf, size_t len,
                     uint64_t remote_addr, uint64_t rkey, uint64_t flags)
{
    /* RMA not on FI_EP_DGRAM */
    if (src->ep_type == FI_EP_DGRAM) return -FI_EINVAL;

    /* Lookup MR at destination */
    sim_mr_t *mr = NULL;
    int rc = uet_sim_mr_lookup(dst, rkey, &mr);
    if (rc) return rc;

    ses_header_t hdr;
    bool has_cq = !!(flags & FI_REMOTE_CQ_DATA);
    uet_build_ses_header(src, dst, SES_OP_WRITE, buf, len,
                          0, rkey, 0, has_cq, &hdr);
    uet_pdm_t pdm = src->select_pdm(src, SES_OP_WRITE);

    /* Check IDEMPOTENT_SAFE for RUDI */
    if (pdm == PDM_RUDI && !(rkey & MR_KEY_IDEMPOTENT_SAFE)) {
        LOG("fi_write: RUDI requires IDEMPOTENT_SAFE; falling back to RUD");
        pdm = PDM_RUD;
    }
    /* Cannot use RUDI if cntr bound (Table 2-16 analogue) */
    if (pdm == PDM_RUDI && mr->cntr_bound) pdm = PDM_RUD;

    LOG("fi_write: len=%zu rkey=0x%016lx remote=0x%016lx pdm=%s",
        len, rkey, remote_addr, pdm_str[pdm]);
    uet_dump_ses_hdr(&hdr);
    uet_dump_mr_key(rkey);

    /* Authorise */
    uint32_t ses_jid = resolve_ses_jobid(src, 0);
    if (!uet_authorize_mr(dst, mr, ses_jid)) return -FI_EACCES;

    /* Perform write */
    void *dest_ptr = (uint8_t *)mr->buf + (remote_addr - (uint64_t)(uintptr_t)mr->buf);
    if (dest_ptr >= mr->buf && (uint8_t*)dest_ptr + len <= (uint8_t*)mr->buf + mr->len)
        memcpy(dest_ptr, buf, len);
    else
        memcpy(mr->buf, buf, len);  /* simplified: write at start */

    /* Completion */
    uet_sim_cq_write(src, 0, FI_WRITE, len, 0, 0, 0);
    uet_sim_cntr_inc(&src->tx_cntr,          len);
    uet_sim_cntr_inc(&src->write_cntr,        len);
    uet_sim_cntr_inc(&dst->remote_write_cntr, len);
    src->stat_rma_writes++;
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════
 * fi_read()  (Table 2-25)  – SES opcode UET_READ
 * ═══════════════════════════════════════════════════════════════════ */
int uet_sim_fi_read(sim_ep_ctx_t *src, sim_ep_ctx_t *dst,
                    void *buf, size_t len,
                    uint64_t remote_addr, uint64_t rkey, uint64_t flags)
{
    if (src->ep_type == FI_EP_DGRAM) return -FI_EINVAL;

    sim_mr_t *mr = NULL;
    int rc = uet_sim_mr_lookup(dst, rkey, &mr);
    if (rc) return rc;

    ses_header_t hdr;
    uet_build_ses_header(src, dst, SES_OP_READ, buf, len,
                          0, rkey, 0, false, &hdr);
    uet_pdm_t pdm = src->select_pdm(src, SES_OP_READ);

    LOG("fi_read: len=%zu rkey=0x%016lx pdm=%s", len, rkey, pdm_str[pdm]);
    uet_dump_ses_hdr(&hdr);

    uint32_t ses_jid = resolve_ses_jobid(src, 0);
    if (!uet_authorize_mr(dst, mr, ses_jid)) return -FI_EACCES;

    /* Perform read */
    size_t copy_len = (len < mr->len) ? len : mr->len;
    memcpy(buf, mr->buf, copy_len);

    /* Completion */
    uet_sim_cq_write(src, 0, FI_READ, len, 0, 0, 0);
    uet_sim_cntr_inc(&src->tx_cntr,         len);
    uet_sim_cntr_inc(&src->read_cntr,        len);
    uet_sim_cntr_inc(&dst->remote_read_cntr, len);
    src->stat_rma_reads++;
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════
 * fi_atomic()  (Table 2-26)  – UET_ATOMIC
 * ═══════════════════════════════════════════════════════════════════ */
int uet_sim_fi_atomic(sim_ep_ctx_t *src, sim_ep_ctx_t *dst,
                      const void *buf, size_t count,
                      uint64_t remote_addr, uint64_t rkey,
                      enum fi_datatype dt, enum fi_op op,
                      uint64_t flags)
{
    if (src->ep_type == FI_EP_DGRAM) return -FI_EINVAL;

    sim_mr_t *mr = NULL;
    int rc = uet_sim_mr_lookup(dst, rkey, &mr);
    if (rc) return rc;

    bool tagged_atomic = !!(flags & FI_TAGGED);
    ses_opcode_t ses_op = tagged_atomic ? SES_OP_TSEND_ATOMIC : SES_OP_ATOMIC;
    ses_header_t hdr;
    uet_build_ses_header(src, dst, ses_op, buf, count,
                          0, rkey, 0, false, &hdr);
    hdr.atomic_opcode   = (uint8_t)op;
    hdr.atomic_datatype = (uint8_t)dt;
    uet_pdm_t pdm = src->select_pdm(src, ses_op);

    LOG("fi_atomic: count=%zu op=%d dt=%d ses_op=%s pdm=%s",
        count, op, dt, ses_op_str[ses_op], pdm_str[pdm]);
    uet_dump_ses_hdr(&hdr);

    uint32_t ses_jid = resolve_ses_jobid(src, 0);
    if (!uet_authorize_mr(dst, mr, ses_jid)) return -FI_EACCES;

    /* Simulate the atomic operation on 8-byte operands (bulk non-fetching) */
    uint64_t *target = (uint64_t *)mr->buf;
    const uint64_t *operand = (const uint64_t *)buf;
    size_t n_elem = count / 8;

    for (size_t i = 0; i < n_elem && i < mr->len/8; i++) {
        switch (op) {
        case FI_SUM:   target[i] += operand[i]; break;
        case FI_BAND:  target[i] &= operand[i]; break;
        case FI_BOR:   target[i] |= operand[i]; break;
        case FI_BXOR:  target[i] ^= operand[i]; break;
        case FI_MIN:   if (operand[i] < target[i]) target[i]=operand[i]; break;
        case FI_MAX:   if (operand[i] > target[i]) target[i]=operand[i]; break;
        case FI_ATOMIC_WRITE: target[i] = operand[i]; break;
        default:       target[i] += operand[i]; break;  /* default: SUM */
        }
    }

    /* Completion */
    uet_sim_cq_write(src, 0, FI_ATOMIC, count, 0, 0, 0);
    uet_sim_cntr_inc(&src->tx_cntr, count);
    src->stat_atomics++;
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════
 * fi_fetch_atomic()  (Table 2-26)  – UET_FETCHING_ATOMIC
 * Returns previous value. Fetching atomics limited to 1 element.
 * ═══════════════════════════════════════════════════════════════════ */
int uet_sim_fi_fetch_atomic(sim_ep_ctx_t *src, sim_ep_ctx_t *dst,
                             const void *buf, size_t count,
                             void *result,
                             uint64_t remote_addr, uint64_t rkey,
                             enum fi_datatype dt, enum fi_op op,
                             uint64_t flags)
{
    if (src->ep_type == FI_EP_DGRAM) return -FI_EINVAL;

    sim_mr_t *mr = NULL;
    int rc = uet_sim_mr_lookup(dst, rkey, &mr);
    if (rc) return rc;

    ses_header_t hdr;
    uet_build_ses_header(src, dst, SES_OP_FETCHING_ATOMIC, buf, count,
                          0, rkey, 0, false, &hdr);
    hdr.atomic_opcode   = (uint8_t)op;
    hdr.atomic_datatype = (uint8_t)dt;
    uet_pdm_t pdm = src->select_pdm(src, SES_OP_FETCHING_ATOMIC);

    LOG("fi_fetch_atomic: count=%zu op=%d dt=%d pdm=%s",
        count, op, dt, pdm_str[pdm]);

    uint32_t ses_jid = resolve_ses_jobid(src, 0);
    if (!uet_authorize_mr(dst, mr, ses_jid)) return -FI_EACCES;

    /* Single unit (spec: fetching atomics limited to single element) */
    uint64_t *target  = (uint64_t *)mr->buf;
    const uint64_t *operand = (const uint64_t *)buf;
    uint64_t *res     = (uint64_t *)result;
    *res = *target;   /* capture previous value */

    switch (op) {
    case FI_SUM:          *target += *operand; break;
    case FI_ATOMIC_WRITE: *target  = *operand; break;
    case FI_CSWAP:        /* compare-and-swap handled in fi_compare_atomic */
        if (*target == hdr.compare_value) *target = hdr.swap_value;
        break;
    default:              *target += *operand; break;
    }

    uet_sim_cq_write(src, 0, FI_ATOMIC|FI_READ, count, 0, 0, 0);
    uet_sim_cntr_inc(&src->tx_cntr, count);
    src->stat_atomics++;
    return 0;
}
