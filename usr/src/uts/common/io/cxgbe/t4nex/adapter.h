/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source. A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * This file is part of the Chelsio T4 support code.
 *
 * Copyright (C) 2011-2013 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */

/*
 * Copyright 2025 Oxide Computer Company
 */

#ifndef __CXGBE_ADAPTER_H
#define	__CXGBE_ADAPTER_H

#include <sys/ddi.h>
#include <sys/mac_provider.h>
#include <sys/ethernet.h>
#include <sys/list.h>
#include <sys/containerof.h>
#include <sys/ddi_ufm.h>
#include <sys/mac_provider.h>

#include "firmware/t4fw_interface.h"
#include "shared.h"

struct adapter;
struct port_info;
typedef struct adapter adapter_t;
struct sge_fl;

#define	FW_IQ_QSIZE	256
#define	FW_IQ_ESIZE	64	/* At least 64 mandated by the firmware spec */

#define	RX_IQ_QSIZE	1024
#define	RX_IQ_ESIZE	64	/* At least 64 so CPL_RX_PKT will fit */

#define	EQ_ESIZE	64	/* All egress queues use this entry size */

#define	RX_FL_ESIZE	64	/* 8 x 64bit addresses */
#define	FL_BUF_PER_BLOCK	8

#define	FL_BUF_SIZES	4

#define	CTRL_EQ_QSIZE	128

#define	TX_EQ_QSIZE	1024
#define	TX_SGL_SEGS	36
#define	TX_WR_FLITS	(SGE_MAX_WR_LEN / 8)

#define	UDBS_SEG_SHIFT	7	/* log2(UDBS_SEG_SIZE) */
#define	UDBS_DB_OFFSET	8	/* offset of the 4B doorbell in a segment */
#define	UDBS_WR_OFFSET	64	/* offset of the work request in a segment */

struct fl_desc {
	uint64_t dptr[FL_BUF_PER_BLOCK];
};

struct fl_sdesc {
	struct rxbuf *rxb;
};

struct tx_desc {
	uint64_t flit[8];
};

struct tx_sdesc {
	mblk_t *m;
	uint32_t txb_used;	/* # of bytes of tx copy buffer used */
	uint16_t hdls_used;	/* # of dma handles used */
	uint16_t desc_used;	/* # of hardware descriptors used */
};

typedef enum t4_iq_flags {
	IQ_ALLOC_HOST	= (1 << 0),	/* host-side resources allocated */
	IQ_ALLOC_DEV	= (1 << 1),	/* device-side resource allocated */
	IQ_INTR		= (1 << 2),	/* iq takes direct interrupt */

	/* Runtime state flags: */
	IQ_ENABLED	= (1 << 3),
	IQ_POLLING	= (1 << 4),
} t4_iq_flags_t;

struct rxbuf_cache_params {
	dev_info_t		*dip;
	ddi_dma_attr_t		dma_attr_rx;
	ddi_device_acc_attr_t	acc_attr_rx;
	size_t			buf_size;
};

struct sge_iq_stats {
	uint64_t sis_processed;	/* # entries processed from IQ */
	uint64_t sis_overflow;	/* # entries bearing overflow flag */
};

/*
 * These values are designed to match up with what is posted to GTS registers
 * when processing an ingress queue.
 *
 * See: t4_iq_update_intr_cfg() and t4_iq_gts_update().
 */
typedef enum t4_gts_config {
	TGC_SE_INTR_ARM		= 1,
	TGC_TIMER0		= (0 << 1),
	TGC_TIMER1		= (1 << 1),
	TGC_TIMER2		= (2 << 1),
	TGC_TIMER3		= (3 << 1),
	TGC_TIMER4		= (4 << 1),
	TGC_TIMER5		= (5 << 1),
	TGC_START_COUNTER	= (6 << 1),
} t4_gts_config_t;

typedef enum t4_iq_type {
	TIQT_EVENT,
	TIQT_ETH_RX,
} t4_iq_type_t;

/* Ingress Queue: T4 is producer, driver is consumer. */
struct sge_iq {
	kmutex_t lock;

	t4_iq_type_t iqtype;
	t4_iq_flags_t flags;

	/*
	 * An IQ can be configured to "forward" its interrupt notifications to
	 * appear as events in a different IQ, rather than as (presumably
	 * MSI(-X)) "real" interrupts.  When this IQ is configured in such a
	 * way, the `intr_evtq` field points to the IQ which will receive those
	 * forwarded interrupt event notifications, subsequently calling
	 * t4_iq_service() on this IQ.
	 */
	struct sge_iq *intr_evtq;
	/*
	 * A list of to-be-serviced IQs is built up as interrupt notification
	 * events are processed in `intr_evtq`.  The `intr_fwd_node` field is
	 * protected by `intr_evtq->lock`, rather than the `lock` of this IQ.
	 */
	list_node_t intr_fwd_node;
	/*
	 * When interrupt forwarding is not in use (such as for IQs which
	 * receive the forwarded notifications themselves), intr_idx holds the
	 * index of the interrupt index assigned to this IQ.
	 */
	uint_t intr_idx;

	ddi_dma_handle_t desc_dhdl;
	ddi_acc_handle_t desc_ahdl;

	uint64_t *desc;		/* KVA of descriptor ring */
	uint64_t desc_ba;	/* bus address of descriptor ring */
	const uint64_t *cdesc;	/* current descriptor (at CIDX) */

	/* Sizing and status */
	uint16_t esize;		/* size (bytes) of each entry in the queue */
	uint16_t qsize;		/* size (# of entries) of the queue */
	uint16_t cidx;		/* consumer index */
	uint16_t pending;	/* # of descs processed since last doorbell */
	uint8_t gen;		/* generation bit */

	t4_gts_config_t gts_rearm; /* GTS config to re-arm queue notification */
	int8_t intr_pktc_idx;	/* packet count threshold index */

	uint16_t cntxt_id;	/* SGE context ID for IQ */
	uint16_t abs_id;	/* absolute SGE ID for IQ */

	struct adapter *adapter; /* associated adapter */
	struct sge_fl *fl;	/* associated freelist (if any) */

	struct sge_iq_stats stats;
};

/*
 * Details used when servicing an IQ as part of polling.
 */
struct t4_poll_req {
	mblk_t	*tpr_mp;
	uint_t	tpr_byte_budget;
};

typedef enum t4_eq_flags {
	/* Initialization state flags: */
	EQ_ALLOC_HOST	= (1 << 0),	/* host-side resources allocated */
	EQ_ALLOC_DEV	= (1 << 1),	/* EQ allocated in device firmware */
	EQ_ALLOC_DESC	= (1 << 2),	/* descriptor inputs allocated */

	/* Runtime state flags: */

	EQ_ENABLED	= (1 << 3),	/* ready for submitted work requests */
	/*
	 * Short on resources (memory and/or descriptors) while attempting to
	 * enqueue work in EQ
	 */
	EQ_CORKED	= (1 << 4),
} t4_eq_flags_t;

/*
 * EQ doorbell mechanisms.
 * These listed in order of preference, which is load-bearing.
 */
typedef enum t4_doorbells {
	DOORBELL_UDB	= (1 << 0),
	DOORBELL_WCWR	= (1 << 1),
	DOORBELL_UDBWC	= (1 << 2),
	DOORBELL_KDB	= (1 << 3),
} t4_doorbells_t;

typedef enum t4_eq_type {
	TEQT_ETH_TX,
	TEQT_FREELIST,
} t4_eq_type_t;

/* Egress Queue: driver is producer, T4 is consumer. */
struct sge_eq {
	kmutex_t lock;

	t4_eq_type_t eqtype;
	t4_eq_flags_t flags;

	ddi_dma_handle_t desc_dhdl;
	ddi_acc_handle_t desc_ahdl;

	void *desc;		/* KVA of descriptor ring */
	uint64_t desc_ba;	/* bus address of descriptor ring */

	/* Sizing and status */
	uint16_t cap;		/* max # of desc, for convenience */
	uint16_t avail;		/* available descriptors, for convenience */
	uint16_t qsize;		/* size (# of entries) of the queue */
	uint16_t esize;		/* size of entries in queue */
	uint16_t cidx;		/* consumer idx (desc idx) */
	uint16_t pidx;		/* producer idx (desc idx) */
	uint16_t pending;	/* # of descriptors used since last doorbell */

	/* Doorbell bits */
	t4_doorbells_t doorbells;
	caddr_t udb;		/* KVA of doorbell (lies within BAR2) */
	uint_t udb_qid;		/* relative qid within the doorbell page */

	struct sge_qstat *spg;	/* status page, for convenience */
	uint16_t iqid;		/* IQ that gets egr_update msg for EQ */
	uint8_t tx_chan;	/* tx channel used by the EQ */
	uint32_t cntxt_id;	/* SGE context id for the EQ */
};

typedef enum t4_fl_flags {
	FL_STARVING	= (1 << 0),	/* on the list of starving fl's */
	FL_DOOMED	= (1 << 1),	/* about to be destroyed */
} t4_fl_flags_t;

struct sge_fl_stats {
	uint64_t copied_up;	/* # of frames copied into mblk and handed up */
	uint64_t passed_up;	/* # of frames wrapped in mblk and handed up */
	uint64_t allocb_fail;	/* # of mblk allocation failures */
};

struct sge_fl {
	struct sge_eq eq;

	/*
	 * Index at which new buffers are to be placed in the FL descriptor
	 * which is currently being produced for the device.
	 */
	uint8_t cidx_sdesc;
	uint8_t pidx_sdesc;

	t4_fl_flags_t flags;
	struct sge_iq *iq;	/* IQ which this FL is associated with */

	struct fl_sdesc *sdesc;	/* KVA of software descriptor ring */
	uint32_t needed;	/* # of buffers needed to fill up fl. */
	uint32_t lowat;		/* # of buffers <= this means fl needs help */
	uint32_t offset;	/* current packet within the larger buffer */
	uint16_t copy_threshold; /* anything this size or less is copied up */

	struct sge_fl_stats stats;

	list_node_t node_sfl;	/* Node in adapter list of starving freelists */
};

struct sge_txq_stats {
	/* stats for common events first */
	uint64_t txpkts;	/* # of ethernet packets */
	uint64_t txbytes;	/* # of ethernet bytes */
	uint64_t txcsum;	/* # of times hardware assisted with checksum */
	uint64_t tso_wrs;	/* # of IPv4 TSO work requests */
	uint64_t imm_wrs;	/* # of work requests with immediate data */
	uint64_t sgl_wrs;	/* # of work requests with direct SGL */
	uint64_t txpkt_wrs;	/* # of txpkt work requests (not coalesced) */
	uint64_t txpkts_wrs;	/* # of coalesced tx work requests */
	uint64_t txpkts_pkts;	/* # of frames in coalesced tx work requests */
	uint64_t txb_used;	/* # of tx copy buffers used (64 byte each) */
	uint64_t hdl_used;	/* # of DMA handles used */

	/* stats for not-that-common events */
	uint32_t txb_full;	/* txb ran out of space */
	uint32_t dma_hdl_failed; /* couldn't obtain DMA handle */
	uint32_t dma_map_failed; /* couldn't obtain DMA mapping */
	uint32_t qfull;		/* out of hardware descriptors */
	uint32_t pullup_early;	/* # of pullups before starting frame's SGL */
	uint32_t pullup_late;	/* # of pullups while building frame's SGL */
	uint32_t pullup_failed;	/* # of failed pullups */
	uint32_t csum_failed;	/* # of csum reqs we failed to fulfill */
};

/* Ethernet packet transmission queue */
struct sge_txq {
	struct sge_eq eq;

	struct port_info *port;
	struct tx_sdesc *sdesc;	/* KVA of software descriptor ring */

	mac_ring_handle_t ring_handle;

	/* DMA handles used for tx */
	ddi_dma_handle_t *tx_dhdl;
	uint32_t tx_dhdl_total;	/* Total # of handles */
	uint32_t tx_dhdl_pidx;	/* next handle to be used */
	uint32_t tx_dhdl_cidx;	/* reclaimed up to this index */
	uint32_t tx_dhdl_avail;	/* # of available handles */

	/* Copy buffers for tx */
	ddi_dma_handle_t txb_dhdl;
	ddi_acc_handle_t txb_ahdl;
	caddr_t txb_va;		/* KVA of copy buffers area */
	uint64_t txb_ba;	/* bus address of copy buffers area */
	uint32_t txb_size;	/* total size */
	uint32_t txb_next;	/* offset of next useable area in the buffer */
	uint32_t txb_avail;	/* # of bytes available */
	uint16_t copy_threshold; /* anything this size or less is copied up */

	kstat_t *ksp;
	struct sge_txq_stats stats;
};

struct sge_rxq_stats {
	/* stats for common events first */
	uint64_t rxcsum;	/* # of times hardware assisted with checksum */
	uint64_t rxpkts;	/* # of ethernet packets */
	uint64_t rxbytes;	/* # of ethernet bytes */
};

/* Ethernet packet receive queue */
struct sge_rxq {
	struct sge_iq iq;
	struct sge_fl fl;	/* Freelist for packet receive buffers */

	struct port_info *port;

	mac_ring_handle_t ring_handle;
	uint64_t ring_gen_num;

	kstat_t *ksp;
	struct sge_rxq_stats stats;
};

typedef enum t4_port_flags {
	TPF_INIT_DONE	= (1 << 0),
	TPF_OPEN	= (1 << 1),
	TPF_VI_ENABLED	= (1 << 2),
} t4_port_flags_t;

typedef enum t4_port_feat {
	CXGBE_HW_LSO	= (1 << 0),
	CXGBE_HW_CSUM	= (1 << 1),
} t4_port_feat_t;


struct port_info {
	kmutex_t	lock;
	dev_info_t	*dip;
	struct adapter	*adapter;
	uint8_t		port_id;

	t4_port_flags_t	flags;
	t4_port_feat_t	features;

	mac_handle_t	mh;
	int		mtu;
	uint8_t		hw_addr[ETHERADDRL];
	int16_t 	xact_addr_filt; /* index of exact MAC address filter */

	uint16_t	rxq_count;	/* # of RX queues */
	uint16_t	rxq_start;	/* index of first RX queue */
	uint16_t	txq_count;	/* # of TX queues */
	uint16_t	txq_start;	/* index of first TX queue */

	/* IQ for queue events, when interrupt is available for it */
	struct sge_iq	intr_iq;

	/* Port attributes/data set by common code: */
	uint16_t	viid;
	uint16_t	rss_size;	/* size of VI's RSS table slice */

	uint8_t		port_type;
	int8_t		mdio_addr;
	uint8_t		mod_type;

	uint8_t		lport;
	uint8_t		tx_chan;
	uint8_t		rx_chan;
	uint8_t		rx_cchan;

	uint8_t		rss_mode;

	uint8_t		tmr_idx;
	int8_t		pktc_idx;
	uint8_t		dbq_timer_idx;

	struct link_config link_cfg;
	uint8_t		macaddr_cnt;

	struct port_stats stats;
	kstat_t *ksp_config;
	kstat_t *ksp_info;
	kstat_t *ksp_fec;

	u8 vivld;
	u8 vin;
	u8 smt_idx;

	/* Mirroring bits utilized by common code (unused by our driver) */
	u16 viid_mirror;
	u8 vivld_mirror;
	u8 vin_mirror;
};

struct sge_info {
	uint_t fl_starve_threshold;
	uint64_t dbq_timer_tick;
	uint16_t dbq_timers[SGE_NDBQTIMERS];

	uint_t stat_len;	/* length of status page at ring end */
	uint_t pktshift;	/* padding between CPL & packet data */
	uint_t fl_align;	/* response queue message alignment */
	uint8_t fwq_tmr_idx;	/* Intr. coalesce timer for FWQ */
	int8_t fwq_pktc_idx;	/* Intr. coalesce count for FWQ */

	struct sge_iq fwq;	/* Firmware event queue */

	uint_t rxq_count;	/* total RX queues (all ports and the rest) */
	uint_t txq_count;	/* total TX queues (all ports and the rest) */
	struct sge_txq *txq;	/* NIC TX queues */
	struct sge_rxq *rxq;	/* NIC RX queues */

	uint_t iq_start;	/* IQ context id map start index */
	uint_t eq_start;	/* EQ context id map start index */
	uint_t iqmap_sz;	/* size of IQ context id map */
	uint_t eqmap_sz;	/* size of EQ context id map */
	struct sge_iq **iqmap;	/* iq->cntxt_id to IQ mapping */
	struct sge_eq **eqmap;	/* eq->cntxt_id to EQ mapping */
	struct sge_fl **flmap;	/* fl->cntxt_id to FL mapping */

	/* Device access and DMA attributes for all the descriptor rings */
	ddi_device_acc_attr_t acc_attr_desc;
	ddi_dma_attr_t	dma_attr_desc;

	/* Device access and DMA attributes for tx buffers */
	ddi_device_acc_attr_t acc_attr_tx;
	ddi_dma_attr_t	dma_attr_tx;

	/* Device access and DMA attributes for RX buffers are in rxb_params */
	kmem_cache_t *rxbuf_cache;
	struct rxbuf_cache_params rxb_params;
};

struct driver_properties {
	uint8_t ethq_tmr_idx;
	int8_t ethq_pktc_idx;
	uint8_t dbq_timer_idx;
	uint8_t fwq_tmr_idx;
	int8_t fwq_pktc_idx;
	int qsize_txq;
	int qsize_rxq;

	uint_t holdoff_timer_us[SGE_NTIMERS];
	uint_t holdoff_pktcnt[SGE_NCOUNTERS];

	bool write_combine;
	bool t4_fw_install;
};

typedef struct t4_mbox_waiter {
	list_node_t node;
	kthread_t *thread;
} t4_mbox_waiter_t;

typedef enum t4_adapter_flags {
	/* Initialization progress status bits */
	TAF_INIT_DONE	= (1 << 0),
	TAF_FW_OK	= (1 << 1),
	TAF_INTR_ALLOC	= (1 << 2),

	/* State & capability bits */
	TAF_MASTER_PF	= (1 << 8),
	TAF_DBQ_TIMER	= (1 << 9),
} t4_adapter_flags_t;

/* Plan for interrupt allocation */
typedef enum t4_intr_plan {
	/* Everything on a single interrupt */
	TIP_SINGLE,
	/* One for device errors, one FWQ (including forwarded intrs) */
	TIP_ERR_QUEUES,
	/* 1 + 1 for errors and FWQ, with rest divided evenly between ports */
	TIP_PER_PORT,
} t4_intr_plan_t;

struct t4_intrs_queues {
	int intr_type;		/* DDI_INTR_TYPE_* */
	t4_intr_plan_t intr_plan; /* Plan for interrupt allocation */
	uint_t intr_count;	/* Number of interrupts to allocate */
	uint_t intr_per_port;	/* Per-port interrupts allocated */

	uint_t shared_iqs;	/* How many IQs are allocated for shared use */

	uint_t port_max_rxq;	/* Max RX queues per port */
	uint_t port_max_txq;	/* Max TX queues per port */
};

struct adapter {
	list_node_t node;
	dev_info_t *dip;
	dev_t dev;

	unsigned int pf;
	unsigned int mbox;

	unsigned int vpd_busy;
	unsigned int vpd_flag;

	u32 t4_bar0;

	uint_t open;	/* character device is open */

	/* PCI config space access handle */
	ddi_acc_handle_t pci_regh;

	/* MMIO register access handle */
	ddi_acc_handle_t regh;
	caddr_t regp;
	/* BAR2 register access handle */
	ddi_acc_handle_t bar2_hdl;
	caddr_t bar2_ptr;

	/* Interrupt information */
	ddi_intr_handle_t *intr_handle;
	int intr_cap;
	uint_t intr_pri;

	struct driver_properties props;
	kstat_t *ksp;
	kstat_t *ksp_stat;

	struct sge_info sge;

	struct port_info *port[MAX_NPORTS];
	uint8_t chan_map[NCHAN];
	uint32_t filter_mode;

	t4_adapter_flags_t flags;
	t4_doorbells_t doorbells;

	unsigned int cfcsum;
	struct adapter_params params;
	struct t4_intrs_queues intr_queue_cfg;

	kmutex_t lock;
	kcondvar_t cv;

	/* Starving free lists */
	kmutex_t sfl_lock;	/* same cache-line as sc_lock? but that's ok */
	list_t sfl_list;
	timeout_id_t sfl_timer;

	/* Sensors */
	id_t temp_sensor;
	id_t volt_sensor;

	ddi_ufm_handle_t *ufm_hdl;

	/* support for single-threading access to adapter mailbox registers */
	kmutex_t mbox_lock;
	kcondvar_t mbox_cv;
	list_t mbox_list;
};

#define	PORT_LOCK(pi)			mutex_enter(&(pi)->lock)
#define	PORT_UNLOCK(pi)			mutex_exit(&(pi)->lock)
#define	PORT_LOCK_ASSERT_OWNED(pi)	ASSERT(mutex_owned(&(pi)->lock))
#define	PORT_LOCK_ASSERT_NOTOWNED(pi)	ASSERT(!mutex_owned(&(pi)->lock))

#define	IQ_LOCK(iq)			mutex_enter(&(iq)->lock)
#define	IQ_UNLOCK(iq)			mutex_exit(&(iq)->lock)
#define	IQ_LOCK_ASSERT_OWNED(iq)	ASSERT(mutex_owned(&(iq)->lock))
#define	IQ_LOCK_ASSERT_NOTOWNED(iq)	ASSERT(!mutex_owned(&(iq)->lock))

#define	EQ_LOCK(eq)			mutex_enter(&(eq)->lock)
#define	EQ_UNLOCK(eq)			mutex_exit(&(eq)->lock)
#define	EQ_LOCK_ASSERT_OWNED(eq)	ASSERT(mutex_owned(&(eq)->lock))
#define	EQ_LOCK_ASSERT_NOTOWNED(eq)	ASSERT(!mutex_owned(&(eq)->lock))

/* Freelist state is protected by its EQ lock */
#define	FL_LOCK(fl)			EQ_LOCK(&(fl)->eq)
#define	FL_UNLOCK(fl)			EQ_UNLOCK(&(fl)->eq)

#define	TXQ_LOCK(txq)			EQ_LOCK(&(txq)->eq)
#define	TXQ_UNLOCK(txq)			EQ_UNLOCK(&(txq)->eq)
#define	TXQ_LOCK_ASSERT_OWNED(txq)	EQ_LOCK_ASSERT_OWNED(&(txq)->eq)
#define	TXQ_LOCK_ASSERT_NOTOWNED(txq)	EQ_LOCK_ASSERT_NOTOWNED(&(txq)->eq)

#define	for_each_txq(pi, iter, txq) \
	txq = &pi->adapter->sge.txq[pi->txq_start]; \
	for (iter = 0; iter < pi->txq_count; ++iter, ++txq)
#define	for_each_rxq(pi, iter, rxq) \
	rxq = &pi->adapter->sge.rxq[pi->rxq_start]; \
	for (iter = 0; iter < pi->rxq_count; ++iter, ++rxq)

static inline struct port_info *
adap2pinfo(struct adapter *sc, int idx)
{
	return (sc->port[idx]);
}

static inline unsigned int t4_use_ldst(struct adapter *adap)
{
	return (adap->flags & TAF_FW_OK);
}

static inline void t4_db_full(struct adapter *adap) {}
static inline void t4_db_dropped(struct adapter *adap) {}

/* Is chip version equal to specified value? */
static inline bool
t4_cver_eq(const adapter_t *adap, uint8_t ver)
{
	return (CHELSIO_CHIP_VERSION(adap->params.chip) == ver);
}

/* Is chip version greater than or equal to specified value? */
static inline bool
t4_cver_ge(const adapter_t *adap, uint8_t ver)
{
	return (CHELSIO_CHIP_VERSION(adap->params.chip) >= ver);
}

/* t4_nexus.c */
int t4_port_full_init(struct port_info *);

uint32_t t4_read_reg(struct adapter *, uint32_t);
void t4_write_reg(struct adapter *, uint32_t, uint32_t);
uint64_t t4_read_reg64(struct adapter *, uint32_t);
void t4_write_reg64(struct adapter *, uint32_t, uint64_t);

void t4_mbox_waiter_add(struct adapter *, t4_mbox_waiter_t *);
void t4_mbox_waiter_remove(struct adapter *, t4_mbox_waiter_t *);
bool t4_mbox_wait_owner(struct adapter *, uint_t, bool);

/* t4_debug.c */
void t4_debug_init(void);
void t4_debug_fini(void);

/* t4_sge.c */
void t4_sge_init(struct adapter *);
int t4_alloc_evt_iqs(struct adapter *);
void t4_free_evt_iqs(struct adapter *);
void t4_port_kstats_init(struct port_info *);
void t4_port_kstats_fini(struct port_info *);
int t4_port_queues_init(struct port_info *);
void t4_port_queues_fini(struct port_info *);
void t4_port_queues_enable(struct port_info *pi);
void t4_port_queues_disable(struct port_info *pi);
uint_t t4_intr_all(caddr_t, caddr_t);
uint_t t4_intr_err(caddr_t, caddr_t);
uint_t t4_intr_fwq(caddr_t, caddr_t);
uint_t t4_intr_port_queue(caddr_t, caddr_t);
void t4_iq_gts_update(struct sge_iq *, t4_gts_config_t, uint16_t);
void t4_iq_update_intr_cfg(struct sge_iq *, uint8_t, int8_t);
void t4_eq_update_dbq_timer(struct sge_eq *, struct port_info *);

mblk_t *t4_eth_tx(void *, mblk_t *);
int t4_iq_service(struct sge_iq *, uint_t, struct t4_poll_req *);

/* t4_mac.c */
void t4_os_link_changed(struct adapter *sc, int idx, int link_stat);
void t4_mac_tx_update(struct port_info *pi, struct sge_txq *txq);
int t4_addmac(void *arg, const uint8_t *ucaddr);
const char **t4_get_priv_props(struct port_info *, size_t *);
extern mac_callbacks_t t4_mac_callbacks;

/* t4_ioctl.c */
int t4_ioctl(struct adapter *sc, int cmd, void *data, int mode);

#endif /* __CXGBE_ADAPTER_H */
