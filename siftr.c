/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2007-2009
 * 	Swinburne University of Technology, Melbourne, Australia.
 * Copyright (c) 2009-2010, The FreeBSD Foundation
 * All rights reserved.
 *
 * Portions of this software were developed at the Centre for Advanced
 * Internet Architectures, Swinburne University of Technology, Melbourne,
 * Australia by Lawrence Stewart under sponsorship from the FreeBSD Foundation.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/******************************************************
 * Statistical Information For TCP Research (SIFTR)
 *
 * A FreeBSD kernel module that adds very basic intrumentation to the
 * TCP stack, allowing internal stats to be recorded to a log file
 * for experimental, debugging and performance analysis purposes.
 ******************************************************/

#include <sys/param.h>
#include <sys/alq.h>
#include <sys/errno.h>
#include <sys/eventhandler.h>
#include <sys/hash.h>
#include <sys/kernel.h>
#include <sys/kthread.h>
#include <sys/lock.h>
#include <sys/mbuf.h>
#include <sys/module.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/reboot.h>
#include <sys/sbuf.h>
#include <sys/sdt.h>
#include <sys/smp.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/sysctl.h>
#include <sys/unistd.h>

#include <net/if.h>
#include <net/if_var.h>
#include <net/pfil.h>
#include <net/route.h>

#include <netinet/in.h>
#include <netinet/in_kdtrace.h>
#include <netinet/in_fib.h>
#include <netinet/in_pcb.h>
#include <netinet/in_systm.h>
#include <netinet/in_var.h>
#include <netinet/ip.h>
#include <netinet/ip_var.h>
#include <netinet/tcp_var.h>

#include <machine/in_cksum.h>

/*
 * The version number X.Y refers:
 * X is the major version number and Y has backward compatible changes
 */
#define MODVERSION	__CONCAT(2,0)
#define MODVERSION_STR	__XSTRING(2) "." __XSTRING(0)
#define SYS_NAME "FreeBSD"

enum {
	HOOK = 0, UNHOOK = 1, SIFTR_EXPECTED_MAX_TCP_FLOWS = 65536,
	SIFTR_DISABLE = 0, SIFTR_ENABLE = 1,
	SIFTR_LOG_FILE_MODE = 0644, SIFTR_IPMODE = 4, MAX_LOG_BATCH_SIZE = 3,
	/*
	 * Hard upper limit on the length of log messages. Bump this up if you
	 * add new data fields such that the line length could exceed the below
	 * value.
	 */
	MAX_LOG_MSG_LEN = 300, SIFTR_ALQ_BUFLEN = (1000 * MAX_LOG_MSG_LEN),
};

static MALLOC_DEFINE(M_SIFTR, "siftr", "dynamic memory used by SIFTR");
static MALLOC_DEFINE(M_SIFTR_PKTNODE, "siftr_pktnode", "SIFTR pkt_node struct");
static MALLOC_DEFINE(M_SIFTR_FLOW_INFO, "flow_info", "SIFTR flow_info struct");
static MALLOC_DEFINE(M_SIFTR_HASHNODE, "siftr_hashnode",
		     "SIFTR flow_hash_node struct");

/* Used as links in the pkt manager queue. */
struct pkt_node {
	/* Direction pkt is travelling. */
	enum {
		DIR_IN = 0,
		DIR_OUT = 1,
	}			direction;
	/* Timestamp of pkt as noted in the pfil hook. */
	struct timeval		tval;
	/* Flowid for the connection. */
	uint32_t		flowid;
	/* Congestion Window (bytes). */
	uint32_t		snd_cwnd;
	/* Slow Start Threshold (bytes). */
	uint32_t		snd_ssthresh;
	/* Sending Window (bytes). */
	uint32_t		snd_wnd;
	/* Receive Window (bytes). */
	uint32_t		rcv_wnd;
	/* TCP control block flags. */
	u_int			t_flags;
	/* More tcpcb flags storage */
	u_int			t_flags2;
	/* Current state of the TCP FSM. */
	uint8_t			conn_state;
	/* Smoothed RTT (usecs). */
	uint32_t		srtt;
	/* Retransmission timeout (usec). */
	uint32_t		rto;
	/* Size of the TCP send buffer in bytes. */
	u_int			snd_buf_hiwater;
	/* Current num bytes in the send socket buffer. */
	u_int			snd_buf_cc;
	/* Size of the TCP receive buffer in bytes. */
	u_int			rcv_buf_hiwater;
	/* Current num bytes in the receive socket buffer. */
	u_int			rcv_buf_cc;
	/* Number of bytes inflight that we are waiting on ACKs for. */
	u_int			sent_inflight_bytes;
	/* Number of segments currently in the reassembly queue. */
	int			t_segqlen;
	/* Flow type for the connection. */
	/* TCP sequence number */
	tcp_seq			th_seq;
	/* TCP acknowledgement number */
	tcp_seq			th_ack;
	/* the length of TCP segment payload in bytes */
	uint32_t		data_sz;
	/* Link to next pkt_node in the list. */
	STAILQ_ENTRY(pkt_node)	nodes;
};

struct flow_info
{
	/* permanent info */
	char	laddr[INET_ADDRSTRLEN];		/* local IP address */
	char	faddr[INET_ADDRSTRLEN];		/* foreign IP address */
	uint16_t	lport;			/* local TCP port */
	uint16_t	fport;			/* foreign TCP port */
	uint32_t	key;			/* flowid of the connection */
	uint8_t		ipver;			/* IP version */
	uint32_t	flowtype;		/* Flow type for the connection. */

	/* infrequently change info */
	uint32_t	mss;			/* Max Segment Size (bytes). */
	u_char		sack_enabled;		/* Is SACK enabled? */
	u_char		snd_scale;		/* Window scaling for snd window. */
	u_char		rcv_scale;		/* Window scaling for recv window. */

	uint32_t	nrecord;		/* num of records in the flow */
};

struct flow_hash_node
{
	uint16_t counter;
	uint32_t last_cwnd;
	struct flow_info const_info;
	LIST_ENTRY(flow_hash_node) nodes;
};

static volatile bool siftr_exit_pkt_manager_thread = 0;
static bool     siftr_enabled = 0;
static bool     siftr_cwnd_filter = 0;
static uint16_t siftr_port_filter = 0;
static uint32_t siftr_pkts_per_log = 1;

static uint32_t tmp_qsize = 0;
static uint32_t tmp_q_usecnt = 0;
static uint32_t total_tmp_qsize = 0;
static uint32_t max_tmp_qsize = 0;
static uint32_t max_str_size = 0;
static uint32_t alq_getn_fail_cnt = 0;
static uint32_t global_flow_cnt = 0;

static char siftr_logfile[PATH_MAX] = "/var/log/siftr.log";
static char siftr_logfile_shadow[PATH_MAX] = "/var/log/siftr.log";
static u_long siftr_hashmask;
STAILQ_HEAD(pkthead, pkt_node) pkt_queue = STAILQ_HEAD_INITIALIZER(pkt_queue);
LIST_HEAD(listhead, flow_hash_node) *counter_hash;
static int wait_for_pkt;
static struct alq *siftr_alq = NULL;
static struct mtx siftr_pkt_queue_mtx;
static struct mtx siftr_pkt_mgr_mtx;
static struct thread *siftr_pkt_manager_thr = NULL;
static char direction[2] = {'i','o'};
static eventhandler_tag siftr_shutdown_tag;

/* Required function prototypes. */
static int siftr_sysctl_enabled_handler(SYSCTL_HANDLER_ARGS);
static int siftr_sysctl_logfile_name_handler(SYSCTL_HANDLER_ARGS);

/* Declare the net.inet.siftr sysctl tree and populate it. */

SYSCTL_DECL(_net_inet_siftr);

SYSCTL_NODE(_net_inet, OID_AUTO, siftr, CTLFLAG_RW | CTLFLAG_MPSAFE, NULL,
    "siftr related settings");

SYSCTL_PROC(_net_inet_siftr, OID_AUTO, enabled,
    CTLTYPE_UINT | CTLFLAG_RW | CTLFLAG_NEEDGIANT,
    &siftr_enabled, 0, &siftr_sysctl_enabled_handler, "IU",
    "switch siftr module operations on/off");

SYSCTL_PROC(_net_inet_siftr, OID_AUTO, logfile,
    CTLTYPE_STRING | CTLFLAG_RW | CTLFLAG_NEEDGIANT, &siftr_logfile_shadow,
    sizeof(siftr_logfile_shadow), &siftr_sysctl_logfile_name_handler, "A",
    "file to save siftr log messages to");

SYSCTL_UINT(_net_inet_siftr, OID_AUTO, ppl, CTLFLAG_RW,
    &siftr_pkts_per_log, 1,
    "number of packets between generating a log message");

SYSCTL_U16(_net_inet_siftr, OID_AUTO, port_filter, CTLFLAG_RW,
    &siftr_port_filter, 0,
    "enable packet filter on a TCP port");

SYSCTL_BOOL(_net_inet_siftr, OID_AUTO, cwnd_filter, CTLFLAG_RW,
    &siftr_cwnd_filter, 0,
    "enable packet filter to record only variance of TCP congestion window");

/* Begin functions. */

static inline struct flow_hash_node *
siftr_find_flow(struct listhead *counter_list, uint32_t id)
{
	struct flow_hash_node *hash_node;
	/*
	 * If the list is not empty i.e. the hash index has
	 * been used by another flow previously.
	 */
	if (LIST_FIRST(counter_list) != NULL) {
		/*
		 * Loop through the hash nodes in the list.
		 * There should normally only be 1 hash node in the list.
		 */
		LIST_FOREACH(hash_node, counter_list, nodes) {
			/*
			 * Check if the key for the pkt we are currently
			 * processing is the same as the key stored in the
			 * hash node we are currently processing.
			 * If they are the same, then we've found the
			 * hash node that stores the counter for the flow
			 * the pkt belongs to.
			 */
			if (hash_node->const_info.key == id) {
				return hash_node;
			}
		}
	}

	return NULL;
}

static inline struct flow_hash_node *
siftr_new_hash_node(struct flow_info info)
{
	struct flow_hash_node *hash_node;
	struct listhead *counter_list;

	counter_list = counter_hash + (info.key & siftr_hashmask);
	/* Create a new hash node to store the flow's constant info. */
	hash_node = malloc(sizeof(struct flow_hash_node), M_SIFTR_HASHNODE,
			   M_NOWAIT|M_ZERO);

	if (hash_node != NULL) {
		/* Initialise our new hash node list entry. */
		hash_node->counter = 0;
		hash_node->last_cwnd = 0;
		hash_node->const_info = info;
		LIST_INSERT_HEAD(counter_list, hash_node, nodes);
		global_flow_cnt++;
		return hash_node;
	} else {
		panic("%s: malloc failed", __func__);
		return NULL;
	}
}

static int
siftr_process_pkt(struct pkt_node * pkt_node, char *buf)
{
	struct flow_hash_node *hash_node;
	struct listhead *counter_list;
	int ret_sz;

	if (pkt_node->flowid == 0) {
		panic("%s: flowid not available", __func__);
	}

	counter_list = counter_hash + (pkt_node->flowid & siftr_hashmask);
	hash_node = siftr_find_flow(counter_list, pkt_node->flowid);

	if (hash_node == NULL) {
		return 0;
	}

	/* Check if we have a variance of the cwnd to record. */
	if (siftr_cwnd_filter && hash_node != NULL) {
		if (hash_node->last_cwnd == pkt_node->snd_cwnd) {
			if (siftr_pkts_per_log > 1) {
				/*
				 * Taking the remainder of the counter divided
				 * by the current value of siftr_pkts_per_log
				 * and storing that in counter provides a neat
				 * way to modulate the frequency of log
				 * messages being written to the log file.
				 */
				hash_node->counter = (hash_node->counter + 1) %
						     siftr_pkts_per_log;
				/*
				 * If we have not seen enough packets since the
				 * last time we wrote a log message for this
				 * connection, return.
				 */
				if (hash_node->counter > 0) {
					return 0;
				}
			} else {
				return 0;
			}
		} else {
			hash_node->last_cwnd = pkt_node->snd_cwnd;
			hash_node->counter = 0;
		}
	}

	hash_node->const_info.nrecord++;

	/* Construct a log message.
	 * cc xxx: check vasprintf()? */
	ret_sz = sprintf(buf,
	    "%c,%jd.%06ld,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,"
	    "%u,%u\n",
	    direction[pkt_node->direction],
	    (intmax_t)pkt_node->tval.tv_sec,
	    pkt_node->tval.tv_usec,
	    pkt_node->flowid,
	    pkt_node->snd_cwnd,
	    pkt_node->snd_ssthresh,
	    pkt_node->snd_wnd,
	    pkt_node->rcv_wnd,
	    pkt_node->t_flags,
	    pkt_node->t_flags2,
	    pkt_node->conn_state,
	    pkt_node->srtt,
	    pkt_node->rto,
	    pkt_node->snd_buf_hiwater,
	    pkt_node->snd_buf_cc,
	    pkt_node->rcv_buf_hiwater,
	    pkt_node->rcv_buf_cc,
	    pkt_node->sent_inflight_bytes,
	    pkt_node->t_segqlen,
	    pkt_node->th_seq,
	    pkt_node->th_ack,
	    pkt_node->data_sz);

	if (ret_sz >= MAX_LOG_MSG_LEN) {
		panic("%s: record size %d larger than max record size %d",
		      __func__, ret_sz, MAX_LOG_MSG_LEN);
	} else if (ret_sz < 0) {
		panic("%s: an encoding error occurred, return value %d",
		      __func__, ret_sz);
	}

	return ret_sz;
}

static void
siftr_pkt_manager_thread(void *arg)
{
	STAILQ_HEAD(pkthead, pkt_node) tmp_pkt_queue =
	    STAILQ_HEAD_INITIALIZER(tmp_pkt_queue);
	struct pkt_node *pkt_node;
	uint8_t draining;
	struct ale *log_buf;
	int ret_sz, cnt = 0;
	char *bufp;

	draining = 2;

	mtx_lock(&siftr_pkt_mgr_mtx);

	/* draining == 0 when queue has been flushed and it's safe to exit. */
	while (draining) {
		/*
		 * Sleep until we are signalled to wake because thread has
		 * been told to exit or until 1 tick has passed.
		 */
		mtx_sleep(&wait_for_pkt, &siftr_pkt_mgr_mtx, PWAIT, "pktwait",
		    1);

		/* Gain exclusive access to the pkt_node queue. */
		mtx_lock(&siftr_pkt_queue_mtx);

		/*
		 * Move pkt_queue to tmp_pkt_queue, which leaves
		 * pkt_queue empty and ready to receive more pkt_nodes.
		 */
		STAILQ_CONCAT(&tmp_pkt_queue, &pkt_queue);

		/*
		 * We've finished making changes to the list. Unlock it
		 * so the pfil hooks can continue queuing pkt_nodes.
		 */
		mtx_unlock(&siftr_pkt_queue_mtx);

		/*
		 * We can't hold a mutex whilst calling siftr_process_pkt
		 * because ALQ might sleep waiting for buffer space.
		 */
		mtx_unlock(&siftr_pkt_mgr_mtx);

		/* cui: find the tmp queue size */
		tmp_qsize = 0;

		while ((pkt_node = STAILQ_FIRST(&tmp_pkt_queue)) != NULL) {
			log_buf = alq_getn(siftr_alq, MAX_LOG_MSG_LEN *
						((STAILQ_NEXT(pkt_node, nodes) != NULL) ?
							MAX_LOG_BATCH_SIZE : 1),
					   ALQ_WAITOK);
 
			if (log_buf != NULL) {
				log_buf->ae_bytesused = 0;
				bufp = log_buf->ae_data;
			} else {
				/*
				 * Should only happen if the ALQ is shutting
				 * down.
				 */
				alq_getn_fail_cnt++;
				bufp = NULL;
			}

			STAILQ_FOREACH(pkt_node, &tmp_pkt_queue, nodes) {
				tmp_qsize++;
				if (log_buf != NULL) {
					ret_sz = siftr_process_pkt(pkt_node,
								   bufp);
					if (max_str_size < ret_sz) {
						max_str_size = ret_sz;
					}

					bufp += ret_sz;
					log_buf->ae_bytesused += ret_sz;
				}
				if (++cnt >= MAX_LOG_BATCH_SIZE)
					break;
			}
			if (log_buf != NULL) {
				alq_post_flags(siftr_alq, log_buf, 0);
			}
			for (; cnt > 0; cnt--) {
				pkt_node = STAILQ_FIRST(&tmp_pkt_queue);
				STAILQ_REMOVE_HEAD(&tmp_pkt_queue, nodes);
				free(pkt_node, M_SIFTR_PKTNODE);
			}
		}

		if (!STAILQ_EMPTY(&tmp_pkt_queue)) {
			panic("%s: SIFTR tmp_pkt_queue not empty after flush",
			      __func__);
		}
		tmp_q_usecnt++;
		total_tmp_qsize += tmp_qsize;
		if (max_tmp_qsize < tmp_qsize) {
			max_tmp_qsize = tmp_qsize;
		}
		mtx_lock(&siftr_pkt_mgr_mtx);

		/*
		 * If siftr_exit_pkt_manager_thread gets set during the window
		 * where we are draining the tmp_pkt_queue above, there might
		 * still be pkts in pkt_queue that need to be drained.
		 * Allow one further iteration to occur after
		 * siftr_exit_pkt_manager_thread has been set to ensure
		 * pkt_queue is completely empty before we kill the thread.
		 *
		 * siftr_exit_pkt_manager_thread is set only after the pfil
		 * hooks have been removed, so only 1 extra iteration
		 * is needed to drain the queue.
		 */
		if (siftr_exit_pkt_manager_thread)
			draining--;
	}

	mtx_unlock(&siftr_pkt_mgr_mtx);

	/* Calls wakeup on this thread's struct thread ptr. */
	kthread_exit();
}

/*
 * Look up an inpcb for a packet. Return the inpcb pointer if found, or NULL
 * otherwise.
 */
static inline struct inpcb *
siftr_findinpcb(struct ip *ip, struct mbuf *m, uint16_t sport, uint16_t dport,
		int dir)
{
	struct inpcb *inp;

	/* We need the tcbinfo lock. */
	INP_INFO_WUNLOCK_ASSERT(&V_tcbinfo);

	if (dir == PFIL_IN)
		inp = in_pcblookup(&V_tcbinfo, ip->ip_src, sport, ip->ip_dst,
				   dport, INPLOOKUP_RLOCKPCB, m->m_pkthdr.rcvif);

	else
		inp = in_pcblookup(&V_tcbinfo, ip->ip_dst, dport, ip->ip_src,
				   sport, INPLOOKUP_RLOCKPCB, m->m_pkthdr.rcvif);

	/* If we can't find the inpcb, bail. */
	return (inp);
}

static inline uint32_t
siftr_get_flowid(struct inpcb *inp, uint32_t *phashtype)
{
	if (inp->inp_flowid == 0) {
		return fib4_calc_packet_hash(inp->inp_laddr, inp->inp_faddr,
					     inp->inp_lport, inp->inp_fport,
					     IPPROTO_TCP, phashtype);
	} else {
		*phashtype = inp->inp_flowtype;
		return inp->inp_flowid;
	}
}

static inline void
siftr_siftdata(struct pkt_node *pn, struct inpcb *inp, struct tcpcb *tp,
	       int dir, int inp_locally_locked)
{
	pn->snd_cwnd = tp->snd_cwnd;
	pn->snd_wnd = tp->snd_wnd;
	pn->rcv_wnd = tp->rcv_wnd;
	pn->t_flags2 = tp->t_flags2;
	pn->snd_ssthresh = tp->snd_ssthresh;
	pn->conn_state = tp->t_state;
	pn->srtt = ((uint64_t)tp->t_srtt * tick) >> TCP_RTT_SHIFT;
	pn->t_flags = tp->t_flags;
	pn->rto = tp->t_rxtcur * tick;
	pn->snd_buf_hiwater = inp->inp_socket->so_snd.sb_hiwat;
	pn->snd_buf_cc = sbused(&inp->inp_socket->so_snd);
	pn->rcv_buf_hiwater = inp->inp_socket->so_rcv.sb_hiwat;
	pn->rcv_buf_cc = sbused(&inp->inp_socket->so_rcv);
	pn->sent_inflight_bytes = tp->snd_max - tp->snd_una;
	pn->t_segqlen = tp->t_segqlen;

	/* We've finished accessing the tcb so release the lock. */
	if (inp_locally_locked)
		INP_RUNLOCK(inp);

	pn->direction = (dir == PFIL_IN ? DIR_IN : DIR_OUT);

	/*
	 * Significantly more accurate than using getmicrotime(), but slower!
	 * Gives true microsecond resolution at the expense of a hit to
	 * maximum pps throughput processing when SIFTR is loaded and enabled.
	 */
	microtime(&pn->tval);
}

/*
 * pfil hook that is called for each IPv4 packet making its way through the
 * stack in either direction.
 * The pfil subsystem holds a non-sleepable mutex somewhere when
 * calling our hook function, so we can't sleep at all.
 * It's very important to use the M_NOWAIT flag with all function calls
 * that support it so that they won't sleep, otherwise you get a panic.
 */
static pfil_return_t
siftr_chkpkt(struct mbuf **m, struct ifnet *ifp, int flags,
    void *ruleset __unused, struct inpcb *inp)
{
	struct pkt_node *pn;
	struct ip *ip;
	struct tcphdr *th;
	struct tcpcb *tp;
	unsigned int ip_hl;
	int inp_locally_locked, dir;
	uint32_t hash_id, hash_type;
	struct listhead *counter_list;
	struct flow_hash_node *hash_node;

	inp_locally_locked = 0;
	dir = PFIL_DIR(flags);

	/*
	 * m_pullup is not required here because ip_{input|output}
	 * already do the heavy lifting for us.
	 */

	ip = mtod(*m, struct ip *);

	/* Only continue processing if the packet is TCP. */
	if (ip->ip_p != IPPROTO_TCP)
		goto ret;

	/*
	 * Create a tcphdr struct starting at the correct offset
	 * in the IP packet. ip->ip_hl gives the ip header length
	 * in 4-byte words, so multiply it to get the size in bytes.
	 */
	ip_hl = (ip->ip_hl << 2);
	th = (struct tcphdr *)((caddr_t)ip + ip_hl);

	/*
	 * Only pkts selected by the tcp port filter
	 * can be inserted into the pkt_queue
	 */
	if ((siftr_port_filter != 0) &&
	    (siftr_port_filter != ntohs(th->th_sport)) &&
	    (siftr_port_filter != ntohs(th->th_dport))) {
		goto ret;
	}

	/*
	 * If the pfil hooks don't provide a pointer to the
	 * inpcb, we need to find it ourselves and lock it.
	 */
	if (inp == NULL) {
		/* Find the corresponding inpcb for this pkt. */
		inp = siftr_findinpcb(ip, *m, th->th_sport, th->th_dport, dir);

		if (inp == NULL)
			goto ret;
		else
			inp_locally_locked = 1;
	}

	INP_LOCK_ASSERT(inp);

	/* Find the TCP control block that corresponds with this packet */
	tp = intotcpcb(inp);

	/*
	 * If we can't find the TCP control block (happens occasionaly for a
	 * packet sent during the shutdown phase of a TCP connection), or the
	 * TCP control block has not initialized (happens during TCPS_SYN_SENT),
	 * bail.
	 */
	if (tp == NULL) {
		panic("%s: tp not available", __func__);
		goto inp_unlock;
	}

	hash_id = siftr_get_flowid(inp, &hash_type);
	counter_list = counter_hash + (hash_id & siftr_hashmask);
	hash_node = siftr_find_flow(counter_list, hash_id);

	/* If this flow hasn't been seen before, we create a new entry. */
	if (hash_node == NULL) {
		struct flow_info info;

		inet_ntoa_r(inp->inp_laddr, info.laddr);
		inet_ntoa_r(inp->inp_faddr, info.faddr);
		info.lport = ntohs(inp->inp_lport);
		info.fport = ntohs(inp->inp_fport);
		info.key = hash_id;
		info.ipver = INP_IPV4;
		info.flowtype = hash_type;

		info.mss = tp->t_maxseg;
		info.sack_enabled = (tp->t_flags & TF_SACK_PERMIT) != 0;
		info.snd_scale = tp->snd_scale;
		info.rcv_scale = tp->rcv_scale;
		info.nrecord = 0;

		hash_node = siftr_new_hash_node(info);
	}

	if (hash_node == NULL) {
		goto inp_unlock;
	}

	pn = malloc(sizeof(struct pkt_node), M_SIFTR_PKTNODE, M_NOWAIT|M_ZERO);

	if (pn == NULL) {
		panic("%s: malloc failed", __func__);
		goto inp_unlock;
	}

	pn->flowid = hash_id;
	pn->th_seq = ntohl(th->th_seq);
	pn->th_ack = ntohl(th->th_ack);
	pn->data_sz = ntohs(ip->ip_len) - (ip->ip_hl << 2) - (th->th_off << 2);

	siftr_siftdata(pn, inp, tp, dir, inp_locally_locked);

	mtx_lock(&siftr_pkt_queue_mtx);
	STAILQ_INSERT_TAIL(&pkt_queue, pn, nodes);
	mtx_unlock(&siftr_pkt_queue_mtx);
	goto ret;

inp_unlock:
	if (inp_locally_locked)
		INP_RUNLOCK(inp);

ret:
	return (PFIL_PASS);
}


VNET_DEFINE_STATIC(pfil_hook_t, siftr_inet_hook);
#define	V_siftr_inet_hook	VNET(siftr_inet_hook)
static int
siftr_pfil(int action)
{
	struct pfil_hook_args pha = {
		.pa_version = PFIL_VERSION,
		.pa_flags = PFIL_IN | PFIL_OUT,
		.pa_modname = "siftr",
		.pa_rulname = "default",
	};
	struct pfil_link_args pla = {
		.pa_version = PFIL_VERSION,
		.pa_flags = PFIL_IN | PFIL_OUT | PFIL_HEADPTR | PFIL_HOOKPTR,
	};

	VNET_ITERATOR_DECL(vnet_iter);

	VNET_LIST_RLOCK();
	VNET_FOREACH(vnet_iter) {
		CURVNET_SET(vnet_iter);

		if (action == HOOK) {
			pha.pa_mbuf_chk = siftr_chkpkt;
			pha.pa_type = PFIL_TYPE_IP4;
			V_siftr_inet_hook = pfil_add_hook(&pha);
			pla.pa_hook = V_siftr_inet_hook;
			pla.pa_head = V_inet_pfil_head;
			(void)pfil_link(&pla);
		} else if (action == UNHOOK) {
			pfil_remove_hook(V_siftr_inet_hook);
		}
		CURVNET_RESTORE();
	}
	VNET_LIST_RUNLOCK();

	return (0);
}

static int
siftr_sysctl_logfile_name_handler(SYSCTL_HANDLER_ARGS)
{
	struct alq *new_alq;
	int error;

	error = sysctl_handle_string(oidp, arg1, arg2, req);

	/* Check for error or same filename */
	if (error != 0 || req->newptr == NULL ||
	    strncmp(siftr_logfile, arg1, arg2) == 0)
		goto done;

	/* file name changed */
	error = alq_open(&new_alq, arg1, curthread->td_ucred,
	    SIFTR_LOG_FILE_MODE, SIFTR_ALQ_BUFLEN, 0);
	if (error != 0)
		goto done;

	/*
	 * If disabled, siftr_alq == NULL so we simply close
	 * the alq as we've proved it can be opened.
	 * If enabled, close the existing alq and switch the old
	 * for the new.
	 */
	if (siftr_alq == NULL) {
		alq_close(new_alq);
	} else {
		alq_close(siftr_alq);
		siftr_alq = new_alq;
	}

	/* Update filename upon success */
	strlcpy(siftr_logfile, arg1, arg2);
done:
	return (error);
}

static int
compare_nrecord(const void *_a, const void *_b)
{
	const struct flow_info *a, *b;

	a = (const struct flow_info *)_a;
	b = (const struct flow_info *)_b;

	if (a->nrecord < b->nrecord)
		return (-1);
	else if (a->nrecord > b->nrecord)
		return (1);

	return (0);
}

static int
siftr_manage_ops(uint8_t action)
{
	struct timeval tval;
	struct flow_hash_node *counter, *tmp_counter;
	struct sbuf *s;
	int i, j, error;
	uint32_t bytes_to_write;
	struct flow_info *arr;

	error = 0;
	arr = NULL;

	/* Init an autosizing sbuf that initially holds 200 chars. */
	if ((s = sbuf_new(NULL, NULL, 200, SBUF_AUTOEXTEND)) == NULL)
		return (-1);

	if (action == SIFTR_ENABLE && siftr_pkt_manager_thr == NULL) {
		/*
		 * Create our alq
		 * XXX: We should abort if alq_open fails!
		 */
		alq_open(&siftr_alq, siftr_logfile, curthread->td_ucred,
		    SIFTR_LOG_FILE_MODE, SIFTR_ALQ_BUFLEN, 0);

		STAILQ_INIT(&pkt_queue);

		siftr_exit_pkt_manager_thread = 0;
		total_tmp_qsize = alq_getn_fail_cnt = tmp_q_usecnt =
			max_str_size = max_tmp_qsize = global_flow_cnt = 0;

		kthread_add(&siftr_pkt_manager_thread, NULL, NULL,
		    &siftr_pkt_manager_thr, RFNOWAIT, 0,
		    "siftr_pkt_manager_thr");

		siftr_pfil(HOOK);

		microtime(&tval);

		sbuf_printf(s,
		    "enable_time_secs=%jd\tenable_time_usecs=%06ld\t"
		    "siftrver=%s\tsysname=%s\tsysver=%u\tipmode=%u\n",
		    (intmax_t)tval.tv_sec, tval.tv_usec, MODVERSION_STR,
		    SYS_NAME, __FreeBSD_version, SIFTR_IPMODE);

		sbuf_finish(s);
		alq_writen(siftr_alq, sbuf_data(s), sbuf_len(s), ALQ_WAITOK);

	} else if (action == SIFTR_DISABLE && siftr_pkt_manager_thr != NULL) {
		/*
		 * Remove the pfil hook functions. All threads currently in
		 * the hook functions are allowed to exit before siftr_pfil()
		 * returns.
		 */
		siftr_pfil(UNHOOK);

		/* This will block until the pkt manager thread unlocks it. */
		mtx_lock(&siftr_pkt_mgr_mtx);

		/* Tell the pkt manager thread that it should exit now. */
		siftr_exit_pkt_manager_thread = 1;

		/*
		 * Wake the pkt_manager thread so it realises that
		 * siftr_exit_pkt_manager_thread == 1 and exits gracefully.
		 * The wakeup won't be delivered until we unlock
		 * siftr_pkt_mgr_mtx so this isn't racy.
		 */
		wakeup(&wait_for_pkt);

		/* Wait for the pkt_manager thread to exit. */
		mtx_sleep(siftr_pkt_manager_thr, &siftr_pkt_mgr_mtx, PWAIT,
		    "thrwait", 0);

		siftr_pkt_manager_thr = NULL;
		mtx_unlock(&siftr_pkt_mgr_mtx);

		microtime(&tval);

		sbuf_printf(s,
		    "disable_time_secs=%jd\tdisable_time_usecs=%06ld\t"
		    "global_flow_cnt=%u\t"
		    "max_tmp_qsize=%u\tavg_tmp_qsize=%ju\tmax_str_size=%u\t"
		    "alq_getn_fail_cnt=%u\t",
		    (intmax_t)tval.tv_sec, tval.tv_usec,
		    global_flow_cnt, max_tmp_qsize,
		    (uintmax_t)(total_tmp_qsize / tmp_q_usecnt),
		    max_str_size, alq_getn_fail_cnt);

		/* Create an array to store all flows' keys and records. */
		arr = malloc(sizeof(struct flow_info) * global_flow_cnt,
			     M_SIFTR_FLOW_INFO, M_NOWAIT|M_ZERO);

		if (arr == NULL) {
			panic("%s: malloc failed for an array of flows", __func__);
		}
		/*
		 * Iterate over the flow hash, printing a summary of each
		 * flowid seen and freeing any malloc'd memory.
		 * The hash consists of an array of LISTs (man 3 queue).
		 */
		for (i = 0, j = 0; i <= siftr_hashmask; i++) {
			LIST_FOREACH_SAFE(counter, counter_hash + i, nodes,
			    tmp_counter) {
					arr[j++] = counter->const_info;
				free(counter, M_SIFTR_HASHNODE);
			}
			LIST_INIT(counter_hash + i);
		}

		if (j > global_flow_cnt) {
			panic("%s: arr[%d] overflow", __func__, j);
		}

		/* sort into ascending ordered list by flow's nrecord */
		qsort(arr, global_flow_cnt, sizeof(arr[0]), compare_nrecord);
		sbuf_printf(s, "flow_list=");
		for (j = 0; j < global_flow_cnt; j++) {
			sbuf_printf(s, "%u,%s,%hu,%s,%hu,%u,%u,%u,%u,%u;",
					arr[j].key,
					arr[j].laddr, arr[j].lport,
					arr[j].faddr, arr[j].fport,
					arr[j].mss, arr[j].sack_enabled,
					arr[j].snd_scale, arr[j].rcv_scale,
					arr[j].nrecord);
		}

		sbuf_printf(s, "\n");
		sbuf_finish(s);

		i = 0;
		do {
			bytes_to_write = min(SIFTR_ALQ_BUFLEN, sbuf_len(s)-i);
			alq_writen(siftr_alq, sbuf_data(s)+i, bytes_to_write, ALQ_WAITOK);
			i += bytes_to_write;
		} while (i < sbuf_len(s));

		alq_close(siftr_alq);
		siftr_alq = NULL;
		total_tmp_qsize = alq_getn_fail_cnt = tmp_q_usecnt =
			max_str_size = max_tmp_qsize = global_flow_cnt = 0;
		free(arr, M_SIFTR_FLOW_INFO);
	} else
		error = EINVAL;

	sbuf_delete(s);

	/*
	 * XXX: Should be using ret to check if any functions fail
	 * and set error appropriately
	 */

	return (error);
}

static int
siftr_sysctl_enabled_handler(SYSCTL_HANDLER_ARGS)
{
	int error;
	uint32_t new;

	new = siftr_enabled;
	error = sysctl_handle_int(oidp, &new, 0, req);
	if (error == 0 && req->newptr != NULL) {
		if (new > 1)
			return (EINVAL);
		else if (new != siftr_enabled) {
			if ((error = siftr_manage_ops(new)) == 0) {
				siftr_enabled = new;
			} else {
				siftr_manage_ops(SIFTR_DISABLE);
			}
		}
	}

	return (error);
}

static void
siftr_shutdown_handler(void *arg, int howto)
{
	if ((howto & RB_NOSYNC) != 0 || SCHEDULER_STOPPED())
		return;

	if (siftr_enabled == 1) {
		siftr_manage_ops(SIFTR_DISABLE);
	}
}

/*
 * Module is being unloaded or machine is shutting down. Take care of cleanup.
 */
static int
deinit_siftr(void)
{
	/* Cleanup. */
	EVENTHANDLER_DEREGISTER(shutdown_pre_sync, siftr_shutdown_tag);
	siftr_manage_ops(SIFTR_DISABLE);
	hashdestroy(counter_hash, M_SIFTR, siftr_hashmask);
	mtx_destroy(&siftr_pkt_queue_mtx);
	mtx_destroy(&siftr_pkt_mgr_mtx);

	return (0);
}

/*
 * Module has just been loaded into the kernel.
 */
static int
init_siftr(void)
{
	siftr_shutdown_tag = EVENTHANDLER_REGISTER(shutdown_pre_sync,
	    siftr_shutdown_handler, NULL, SHUTDOWN_PRI_FIRST);

	/* Initialise our flow counter hash table. */
	counter_hash = hashinit(SIFTR_EXPECTED_MAX_TCP_FLOWS, M_SIFTR,
	    &siftr_hashmask);

	mtx_init(&siftr_pkt_queue_mtx, "siftr_pkt_queue_mtx", NULL, MTX_DEF);
	mtx_init(&siftr_pkt_mgr_mtx, "siftr_pkt_mgr_mtx", NULL, MTX_DEF);

	/* Print message to the user's current terminal. */
	uprintf("\nStatistical Information For TCP Research (SIFTR) %s\n",
	    MODVERSION_STR);

	return (0);
}

/*
 * This is the function that is called to load and unload the module.
 * When the module is loaded, this function is called once with
 * "what" == MOD_LOAD
 * When the module is unloaded, this function is called twice with
 * "what" = MOD_QUIESCE first, followed by "what" = MOD_UNLOAD second
 * When the system is shut down e.g. CTRL-ALT-DEL or using the shutdown command,
 * this function is called once with "what" = MOD_SHUTDOWN
 * When the system is shut down, the handler isn't called until the very end
 * of the shutdown sequence i.e. after the disks have been synced.
 */
static int
siftr_load_handler(module_t mod, int what, void *arg)
{
	int ret;

	switch (what) {
	case MOD_LOAD:
		ret = init_siftr();
		break;

	case MOD_QUIESCE:
	case MOD_SHUTDOWN:
		ret = deinit_siftr();
		break;

	case MOD_UNLOAD:
		ret = 0;
		break;

	default:
		ret = EINVAL;
		break;
	}

	return (ret);
}

static moduledata_t siftr_mod = {
	.name = "siftr",
	.evhand = siftr_load_handler,
};

/*
 * Param 1: name of the kernel module
 * Param 2: moduledata_t struct containing info about the kernel module
 *          and the execution entry point for the module
 * Param 3: From sysinit_sub_id enumeration in /usr/include/sys/kernel.h
 *          Defines the module initialisation order
 * Param 4: From sysinit_elem_order enumeration in /usr/include/sys/kernel.h
 *          Defines the initialisation order of this kld relative to others
 *          within the same subsystem as defined by param 3
 */
DECLARE_MODULE(siftr, siftr_mod, SI_SUB_LAST, SI_ORDER_ANY);
MODULE_DEPEND(siftr, alq, 1, 1, 1);
MODULE_VERSION(siftr, MODVERSION);
