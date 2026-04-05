# UET / libfabric v2.0 Complete Simulation
## Ultra Ethernet Consortium Specification §2.2 (pages 66-121)

---

## Overview

This simulation implements the full mapping between **libfabric v2.0 (OFI)**
and the **Ultra Ethernet Transport (UET v1.0)** as specified in §2.2 of the
UE Consortium specification.

---

## File Layout

```
uet_sim/
├── uet_sim.h          ← All types, constants, struct definitions, API declarations
├── uet_sim_core.c     ← Core engine: addressing, JobID, auth, PDM, SES headers,
│                         MR management, CQ, counters, security
├── uet_sim_xfer.c     ← Data-transfer operations: fi_msg, fi_tagged, fi_rma,
│                         fi_atomic, rendezvous, deferrable-send
├── uet_sim_main.c     ← 20-test driver covering every spec section
└── Makefile
```

---

## Build

```bash
# libfabric must be installed:
#   sudo apt install libfabric-dev       # Debian/Ubuntu
#   sudo dnf install libfabric-devel     # Fedora/RHEL

make        # compile
make run    # compile and run all 20 tests
```

---

## Specification Coverage

| Spec Section | Feature | Source File |
|---|---|---|
| 2.2   | Libfabric / UET overview, libfabric software architecture | all |
| 2.2.1 | Application use cases (CCL, MPI, SHMEM, UD) – Table 2-3 | uet_sim.h |
| 2.2.2 | UET Profiles (AI Base, AI Full, HPC) – Table 2-4/2-5 | uet_sim.h, uet_sim_core.c |
| 2.2.2.1 | Profile negotiation & inter-profile interoperability – Table 2-6 | uet_sim_core.c Test-2,19 |
| 2.2.3 | Provider configuration parameters – Table 2-7 | uet_sim.h (msg/tag rendezvous sizes) |
| 2.2.4 | JobID concepts (ses.JobID, privileged entity) | uet_sim_core.c |
| 2.2.4.1 | JobID at job-init time; UET Control API mapping – Table 2-8 | uet_sim_core.c Test-3 |
| 2.2.4.2 | Fallback JobID (value 16777215) | uet_sim_core.c Test-20 |
| 2.2.4.3 | Authorization: recv buffers & MR – indirect/direct/AV methods | uet_sim_core.c Test-14 |
| 2.2.4.3.1 | Untagged buffer authorization | uet_sim_xfer.c |
| 2.2.4.3.2 | Tagged buffer authorization | uet_sim_xfer.c |
| 2.2.4.3.3 | Memory region authorization (fi_mr_regattr) | uet_sim_core.c |
| 2.2.4.4 | JobID selection for data transmission | uet_sim_core.c resolve_ses_jobid() |
| 2.2.5 | Libfabric APIs – all four categories | uet_sim_core.c, uet_sim_xfer.c |
| 2.2.5.1 | FI_ADDR_UET addressing format – Table 2-10 | uet_sim.h, uet_sim_core.c Test-1 |
| 2.2.5.2 | Discovery APIs (fi_version, fi_getinfo) – Table 2-11/2-12 | uet_sim.h (API stubs) |
| 2.2.5.3 | Communication & completion APIs | uet_sim_core.c |
| 2.2.5.3.4 | fi_mr_reg / fi_mr_key; Memory key format – Table 2-13 | uet_sim_core.c Test-12 |
| 2.2.5.3.4.1 | MR key format: IDEMPOTENT_SAFE, OPTIMIZED, RKEY – Table 2-14/15 | uet_sim.h, Test-12 |
| 2.2.5.3.5 | fi_endpoint / fi_ep_bind, FI_EP_RDM / FI_EP_DGRAM | uet_sim_core.c |
| 2.2.5.3.5.1 | UET address assignment architecture – Figure 2-9 | uet_sim_core.c |
| 2.2.5.3.7 | fi_cq_open / fi_cntr_open; per-profile counter req – Table 2-20 | uet_sim_core.c Test-16 |
| 2.2.5.3.8 | fi_av_open / fi_av_insert; FI_AV_TABLE | uet_sim_core.c |
| 2.2.5.4.1 | fi_msg() APIs – Table 2-21/2-22 | uet_sim_xfer.c Test-4,5,6 |
| 2.2.5.4.1.1 | Unexpected messages | uet_sim_xfer.c |
| 2.2.5.4.1.2 | Message rendezvous / deferrable send | uet_sim_xfer.c Test-9,10 |
| 2.2.5.4.2 | fi_tagged() APIs – Table 2-23/2-24 | uet_sim_xfer.c Test-7,8 |
| 2.2.5.4.2.1 | Tagged initiator ID matching (ses.initiator) | uet_sim_xfer.c |
| 2.2.5.4.2.2 | Tagged message rendezvous | uet_sim_xfer.c |
| 2.2.5.4.3 | fi_rma() APIs – Table 2-25; UET_READ / UET_WRITE | uet_sim_xfer.c Test-11 |
| 2.2.5.4.4 | fi_atomic() APIs – Table 2-26; bulk non-fetching & fetching | uet_sim_xfer.c Test-13 |
| 2.2.5.4.5 | Collective APIs concept | uet_sim.h (described) |
| 2.2.6 | Packet delivery modes: UUD/RUD/ROD/RUDI – Tables 2-29/30/31 | uet_sim_core.c Test-15 |
| 2.2.7 | Traffic classes, DSCP – Table 2-32 | uet_sim.h |
| 2.2.8 | Transmit/receive queues, independent tagged/untagged | uet_sim_xfer.c |
| 2.2.9 | Security protocol, binding params, rekeying – Table 2-33/34 | uet_sim_core.c Test-17 |
| 2.2.10 | Wire-protocol header mapping (IP, TSS, PDS, SES) – Table 2-36..44 | uet_sim_core.c Test-18 |
| 2.2.11 | Linux UET Control API (Netlink) – Figure 2-16/17 | uet_sim.h (enum stubs) |

---

## Three UET Profiles

| Profile | Priority | Key Capabilities |
|---|---|---|
| AI Base | 0 | FI_MSG, FI_WRITE, FI_ATOMIC, RUD/ROD PDMs |
| AI Full | 1 | + FI_TAGGED (exact), FI_READ, deferrable send, FI_FETCH_ATOMIC |
| HPC | 2 | + FI_TAGGED (wildcard), rendezvous, RUDI, FI_COMPARE_ATOMIC, AV JobID |

---

## JobID Methods

| Method | auth_key_size | Description |
|---|---|---|
| Indirect | 0 | Provider supplies JobID automatically (default) |
| Direct | 3 | JobID carried in auth_key attribute of endpoint |
| AV | FI_AV_AUTH_KEY | JobID inserted into address vector; HPC MUST support |

---

## Packet Delivery Mode Selection

- **FI_EP_DGRAM** always uses **UUD**
- **FI_EP_RDM (AI Base/Full)**: selects **RUD** or **ROD** based on send/R-W ordering
- **FI_EP_RDM (HPC)**: additionally selects **RUDI** for idempotent RMA operations

---

## SES Header Formats

| Format | Trigger |
|---|---|
| Standard | default for most operations |
| Non-Matching (Optimized) | OPTIMIZED bit set, size ≤ MTU, no CQ data |
| Small Message / Small RMA | tagged send ≤ MTU, or RMA ≤ MTU without CQ data |
| Deferrable Send | AI Full profile large messages |
| Rendezvous Extension | HPC large messages |
| Atomic Extension | fi_atomic() operations |
| Compare-and-Swap | fi_compare_atomic() |
| Response | SES ACKs / data responses |
# uet_simulation
# uet_simulation
