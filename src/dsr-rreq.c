/* Copyright (C) Uppsala University
 *
 * This file is distributed under the terms of the GNU general Public
 * License (GPL), see the file LICENSE
 *
 * Author: Erik Nordström, <erikn@it.uu.se>
 */
#ifdef __KERNEL__
#include <linux/proc_fs.h>
#include <linux/timer.h>
#include <net/ip.h>
#include <linux/random.h>

#include "dsr-dev.h"
#endif

#ifdef NS2
#include "ns-agent.h"
#endif

#include "debug.h"
#include "dsr.h"
#include "tbl.h"
#include "dsr-rrep.h"
#include "dsr-rreq.h"
#include "dsr-opt.h"
#include "link-cache.h"
#include "send-buf.h"
#include "neigh.h"

#ifndef NS2

#define RREQ_TBL_PROC_NAME "dsr_rreq_tbl"

static TBL(rreq_tbl, RREQ_TBL_MAX_LEN);
static unsigned int rreq_seqno;
#endif

#ifndef MAXTTL
#define MAXTTL 255
#endif

#define STATE_IDLE 0
#define STATE_IN_ROUTE_DISC 1

struct rreq_tbl_entry
{
	list_t l;
	int state;
	struct in_addr node_addr;
	int ttl;
	DSRUUTimer *timer;
	struct timeval tx_time;
	struct timeval last_used;
	usecs_t timeout;
	unsigned int num_rexmts;
	struct tbl rreq_id_tbl;
};

struct id_entry
{
	list_t l;
	struct in_addr trg_addr;
	unsigned short id;
};
struct rreq_tbl_query
{
	struct in_addr *initiator;
	struct in_addr *target;
	unsigned int *id;
};

static inline int crit_addr(void *pos, void *data)
{
	struct rreq_tbl_entry *e = (struct rreq_tbl_entry *)pos;
	struct in_addr *a = (struct in_addr *)data;

	if (e->node_addr.s_addr == a->s_addr)
		return 1;
	return 0;
}

static inline int crit_duplicate(void *pos, void *data)
{
	struct rreq_tbl_entry *e = (struct rreq_tbl_entry *)pos;
	struct rreq_tbl_query *q = (struct rreq_tbl_query *)data;

	if (e->node_addr.s_addr == q->initiator->s_addr)
	{
		list_t *p;

		list_for_each(p, &e->rreq_id_tbl.head)
		{
			struct id_entry *id_e = (struct id_entry *)p;

			if (id_e->trg_addr.s_addr == q->target->s_addr &&
				id_e->id == *(q->id))
				return 1;
		}
	}
	return 0;
}

void NSCLASS rreq_tbl_set_max_len(unsigned int max_len)
{
	rreq_tbl.max_len = max_len;
}
#ifdef __KERNEL__
static int rreq_tbl_print(struct tbl *t, char *buf)
{
	list_t *pos1, *pos2;
	int len = 0;
	int first = 1;
	struct timeval now;

	gettime(&now);

	DSR_READ_LOCK(&t->lock);

	len +=
		sprintf(buf, "# %-15s %-6s %-8s %15s:%s\n", "IPAddr", "TTL", "Used",
				"TargetIPAddr", "ID");

	list_for_each(pos1, &t->head)
	{
		struct rreq_tbl_entry *e = (struct rreq_tbl_entry *)pos1;
		struct id_entry *id_e;

		if (TBL_EMPTY(&e->rreq_id_tbl))
			len +=
				sprintf(buf + len, "  %-15s %-6u %-8lu %15s:%s\n",
						print_ip(e->node_addr), e->ttl,
						timeval_diff(&now, &e->last_used) / 1000000,
						"-", "-");
		else
		{
			id_e = (struct id_entry *)TBL_FIRST(&e->rreq_id_tbl);
			len +=
				sprintf(buf + len, "  %-15s %-6u %-8lu %15s:%u\n",
						print_ip(e->node_addr), e->ttl,
						timeval_diff(&now, &e->last_used) / 1000000,
						print_ip(id_e->trg_addr), id_e->id);
		}
		list_for_each(pos2, &e->rreq_id_tbl.head)
		{
			id_e = (struct id_entry *)pos2;
			if (!first)
				len +=
					sprintf(buf + len, "%49s:%u\n",
							print_ip(id_e->trg_addr), id_e->id);
			first = 0;
		}
	}

	DSR_READ_UNLOCK(&t->lock);
	return len;
}
#endif /* __KERNEL__ */

void NSCLASS rreq_tbl_timeout(unsigned long data)
{
	struct rreq_tbl_entry *e = (struct rreq_tbl_entry *)data;
	struct timeval expires;

	if (!e)
		return;

	tbl_detach(&rreq_tbl, &e->l);

	DEBUG("RREQ Timeout dst=%s timeout=%lu rexmts=%d \n",
		  print_ip(e->node_addr), e->timeout, e->num_rexmts);

	if (e->num_rexmts >= ConfVal(MaxRequestRexmt))
	{
		DEBUG("MAX RREQs reached for %s\n", print_ip(e->node_addr));

		e->state = STATE_IDLE;

		/* 		DSR_WRITE_UNLOCK(&rreq_tbl); */
		tbl_add_tail(&rreq_tbl, &e->l);
		return;
	}

	e->num_rexmts++;

	/* if (e->ttl == 1) */
	/* 		e->timeout = ConfValToUsecs(RequestPeriod);  */
	/* 	else */
	e->timeout *= 2; /* Double timeout */

	e->ttl *= 2; /* Double TTL */

	if (e->ttl > MAXTTL)
		e->ttl = MAXTTL;

	if (e->timeout > ConfValToUsecs(MaxRequestPeriod))
		e->timeout = ConfValToUsecs(MaxRequestPeriod);

	gettime(&e->last_used);

	dsr_rreq_send(e->node_addr, e->ttl);

	expires = e->last_used;
	timeval_add_usecs(&expires, e->timeout);

	/* Put at end of list */
	tbl_add_tail(&rreq_tbl, &e->l);

	set_timer(e->timer, &expires);
}

struct rreq_tbl_entry *NSCLASS __rreq_tbl_entry_create(struct in_addr node_addr)
{
	struct rreq_tbl_entry *e;

	e = (struct rreq_tbl_entry *)MALLOC(sizeof(struct rreq_tbl_entry),
										GFP_ATOMIC);

	if (!e)
		return NULL;

	e->state = STATE_IDLE;
	e->node_addr = node_addr;
	e->ttl = 0;
	memset(&e->tx_time, 0, sizeof(struct timeval));
	;
	e->num_rexmts = 0;
#ifdef NS2
	e->timer = new DSRUUTimer(this, "RREQTblTimer");
#else
	e->timer = MALLOC(sizeof(DSRUUTimer), GFP_ATOMIC);
#endif

	if (!e->timer)
	{
		FREE(e);
		return NULL;
	}

	init_timer(e->timer);

	e->timer->function = &NSCLASS rreq_tbl_timeout;
	e->timer->data = (unsigned long)e;

	INIT_TBL(&e->rreq_id_tbl, ConfVal(RequestTableIds));

	return e;
}

struct rreq_tbl_entry *NSCLASS __rreq_tbl_add(struct in_addr node_addr)
{
	struct rreq_tbl_entry *e;

	e = __rreq_tbl_entry_create(node_addr);

	if (!e)
		return NULL;

	if (TBL_FULL(&rreq_tbl))
	{
		struct rreq_tbl_entry *f;

		f = (struct rreq_tbl_entry *)TBL_FIRST(&rreq_tbl);

		__tbl_detach(&rreq_tbl, &f->l);

		del_timer_sync(f->timer);
#ifdef NS2
		delete f->timer;
#else
		FREE(f->timer);
#endif
		tbl_flush(&f->rreq_id_tbl, NULL);

		FREE(f);
	}
	__tbl_add_tail(&rreq_tbl, &e->l);

	return e;
}

int NSCLASS
rreq_tbl_add_id(struct in_addr initiator, struct in_addr target,
				unsigned short id)
{
	struct rreq_tbl_entry *e;
	struct id_entry *id_e;
	int res = 0;

	DSR_WRITE_LOCK(&rreq_tbl.lock);

	e = (struct rreq_tbl_entry *)__tbl_find(&rreq_tbl, &initiator,
											crit_addr);

	if (!e)
		e = __rreq_tbl_add(initiator);
	else
	{
		/* Put it last in the table */
		__tbl_detach(&rreq_tbl, &e->l);
		__tbl_add_tail(&rreq_tbl, &e->l);
	}

	if (!e)
	{
		res = -ENOMEM;
		goto out;
	}

	gettime(&e->last_used);

	if (TBL_FULL(&e->rreq_id_tbl))
		tbl_del_first(&e->rreq_id_tbl);

	id_e = (struct id_entry *)MALLOC(sizeof(struct id_entry), GFP_ATOMIC);

	if (!id_e)
	{
		res = -ENOMEM;
		goto out;
	}

	id_e->trg_addr = target;
	id_e->id = id;

	tbl_add_tail(&e->rreq_id_tbl, &id_e->l);
out:
	DSR_WRITE_UNLOCK(&rreq_tbl.lock);

	return 1;
}

int NSCLASS rreq_tbl_route_discovery_cancel(struct in_addr dst)
{
	struct rreq_tbl_entry *e;

	e = (struct rreq_tbl_entry *)tbl_find_detach(&rreq_tbl, &dst,
												 crit_addr);

	if (!e)
	{
		DEBUG("%s not in RREQ table\n", print_ip(dst));
		return -1;
	}

	if (e->state == STATE_IN_ROUTE_DISC)
		del_timer_sync(e->timer);

	e->state = STATE_IDLE;
	gettime(&e->last_used);

	tbl_add_tail(&rreq_tbl, &e->l);

	return 1;
}
// 该函数功能为发现到 target 的路由 成功返回1 ，已经寻找了返回0， 建立表项内存不足返回 -ENOMEM
int NSCLASS dsr_rreq_route_discovery(struct in_addr target)
{
	struct rreq_tbl_entry *e;
	int ttl, res = 0;
	struct timeval expires; //有效期

#define TTL_START 1

	DSR_WRITE_LOCK(&rreq_tbl.lock); // 获得 rreq_tbl 的写锁

	e = (struct rreq_tbl_entry *)__tbl_find(&rreq_tbl, &target, crit_addr);
	//  查询 req_tbl 中是否有指向 target 的表项
	if (!e)
		e = __rreq_tbl_add(target); // 没有就添加表项
	else
	{
		/* Put it last in the table */
		__tbl_detach(&rreq_tbl, &e->l);
		__tbl_add_tail(&rreq_tbl, &e->l);
		//有就 把他从表中原来位置移除并放入最后
	}

	if (!e)
	{
		// 如果未成功生成表项 返回错误-内存不足
		res = -ENOMEM;
		goto out;
	}

	if (e->state == STATE_IN_ROUTE_DISC)
	{
		// 如果该表项的状态是 地址已经被发出用于路由请求，则退出
		DEBUG("Route discovery for %s already in progress\n",
			  print_ip(target));
		goto out;
	}
	// 否则开始路由寻找
	DEBUG("Route discovery for %s\n", print_ip(target));
	// 将当前时间填入 last_used 位
	gettime(&e->last_used);
	e->ttl = ttl = TTL_START;
	/* The draft does not actually specify how these Request Timeout values
	 * should be used... ??? I am just guessing here. */

	if (e->ttl == 1)
		e->timeout = ConfValToUsecs(NonpropRequestTimeout);
	else
		e->timeout = ConfValToUsecs(RequestPeriod);
	// 改变 e 状态为已在查找
	e->state = STATE_IN_ROUTE_DISC;
	e->num_rexmts = 0;

	expires = e->last_used;
	timeval_add_usecs(&expires, e->timeout);
	// 计算expires 为 e->last_used+e->timeout
	set_timer(e->timer, &expires);
	// 设置定时器，借助NS2仿真中的 TimerHandler 类
	DSR_WRITE_UNLOCK(&rreq_tbl.lock); // 解 tbl 写锁

	dsr_rreq_send(target, ttl);
	// 发送查询报文
	return 1;
out:
	DSR_WRITE_UNLOCK(&rreq_tbl.lock);

	return res;
}
// 检查 req_tbl 中是否有 initiator->target 的表项，有返回1，没有返回0
int NSCLASS dsr_rreq_duplicate(struct in_addr initiator, struct in_addr target,
							   unsigned int id)
{
	struct
	{
		struct in_addr *initiator;
		struct in_addr *target;
		unsigned int *id;
	} d;

	d.initiator = &initiator;
	d.target = &target;
	d.id = &id;

	return in_tbl(&rreq_tbl, &d, crit_duplicate);
}
// 初始化 并返回 rreq_opt
static struct dsr_rreq_opt *dsr_rreq_opt_add(char *buf, unsigned int len,
											 struct in_addr target,
											 unsigned int seqno)
{
	struct dsr_rreq_opt *rreq_opt;

	if (!buf || len < DSR_RREQ_HDR_LEN)
		return NULL;

	rreq_opt = (struct dsr_rreq_opt *)buf;

	rreq_opt->type = DSR_OPT_RREQ;
	rreq_opt->length = 6;
	rreq_opt->id = htons(seqno);
	rreq_opt->target = target.s_addr;

	return rreq_opt;
}
// 发送 dsr_rreq 包， 发送成功返回0 ， 错误返回 -1
int NSCLASS dsr_rreq_send(struct in_addr target, int ttl)
{
	struct dsr_pkt *dp;
	char *buf;
	int len = DSR_OPT_HDR_LEN + DSR_RREQ_HDR_LEN;

	dp = dsr_pkt_alloc(NULL);

	if (!dp)
	{
		DEBUG("Could not allocate DSR packet\n");
		return -1;
	}
	// 发送方式为广播
	dp->dst.s_addr = DSR_BROADCAST;
	dp->nxt_hop.s_addr = DSR_BROADCAST;
	// 填入自己的地址
	dp->src = my_addr();
	// 为 dp 申请头部空间
	buf = dsr_pkt_alloc_opts(dp, len);

	if (!buf)
		goto out_err;
	// 构建网络层 ip 头
	dp->nh.iph =
		dsr_build_ip(dp, dp->src, dp->dst, IP_HDR_LEN, IP_HDR_LEN + len,
					 IPPROTO_DSR, ttl);

	if (!dp->nh.iph)
		goto out_err;
	// 构建DSR 可选头部
	dp->dh.opth = dsr_opt_hdr_add(buf, len, DSR_NO_NEXT_HDR_TYPE);

	if (!dp->dh.opth)
	{
		DEBUG("Could not create DSR opt header\n");
		goto out_err;
	}

	buf += DSR_OPT_HDR_LEN;
	len -= DSR_OPT_HDR_LEN;
	// 构建 RREQ 头
	dp->rreq_opt = dsr_rreq_opt_add(buf, len, target, ++rreq_seqno);

	if (!dp->rreq_opt)
	{
		DEBUG("Could not create RREQ opt\n");
		goto out_err;
	}
#ifdef NS2
	DEBUG("Sending RREQ src=%s dst=%s target=%s ttl=%d iph->saddr()=%d\n",
		  print_ip(dp->src), print_ip(dp->dst), print_ip(target), ttl,
		  dp->nh.iph->saddr());
#endif

	dp->flags |= PKT_XMIT_JITTER;
	// 将 dsr_packet 包发送出去
	XMIT(dp);

	return 0;

out_err:
	dsr_pkt_free(dp);

	return -1;
}
// 接受 rreq 报文 处理并选择回复或转发
// 返回值：
// 1. DSR_PKT_NONE 过程中已经发送过 rrep 报文而不需要上层函数再发送返回此值 - 自己是rreq终点或有 我->终点 路由缓存 返回
/* 2. DSR_PKT_ERROR 出现错误时返回 - 多个 rreq_opt， 未成功提取到 rreq_opt ，或未成功翻转为 srt_rev （ 路径为空
 * 3. DSR_PKT_DROP  已经接收过该报文，报文被丢弃
 * 4. DSR_PKT_FORWARD_RREQ 需要进行转发，由上层函数负责转发
 */
int NSCLASS dsr_rreq_opt_recv(struct dsr_pkt *dp, struct dsr_rreq_opt *rreq_opt)
{
	struct in_addr myaddr;
	struct in_addr trg; // target 缩写 ， 保存 rreq_opt 的目的端地址
	struct dsr_srt *srt_rev, *srt_rc;
	int action = DSR_PKT_NONE;
	int i, n;
	// 参数为 NULL ，或 已经在混杂模式被接收了
	if (!dp || !rreq_opt || dp->flags & PKT_PROMISC_RECV)
		return DSR_PKT_DROP;
	// rreq_opt 可选报文段数目 +1
	dp->num_rreq_opts++;
	// 如果原有 rreq_opts ,则重复
	if (dp->num_rreq_opts > 1)
	{
		DEBUG("More than one RREQ opt!!! - Ignoring\n");
		return DSR_PKT_ERROR;
	}
	// 将报文的 rreq_opt 填上在上层函数已经提取转换后的 rreq_opt 可选报文段
	dp->rreq_opt = rreq_opt;
	// 获取自己的地址
	myaddr = my_addr();

	trg.s_addr = rreq_opt->target;
	// 查找 rreq_tbl 是否已经存在了这样一个 rreq 报文，有就返回
	if (dsr_rreq_duplicate(dp->src, trg, ntohs(rreq_opt->id)))
	{
		DEBUG("Duplicate RREQ from %s\n", print_ip(dp->src));
		return DSR_PKT_DROP;
	}
	// rreq_tbl 中没有就填入进去
	// 这里稍有冗余，在 rreq_tbl_add_id 中又 find 了一下，但其是 duplicate 中已经找过了，这里一定是没有的
	rreq_tbl_add_id(dp->src, trg, ntohs(rreq_opt->id));
	// 转发路径为 源地址到自己，报文中的路径
	dp->srt = dsr_srt_new(dp->src, myaddr, DSR_RREQ_ADDRS_LEN(rreq_opt),
						  (char *)rreq_opt->addrs);
	// srt 为 NULL，未成功提取到路径信息
	if (!dp->srt)
	{
		DEBUG("Could not extract source route\n");
		return DSR_PKT_ERROR;
	}
	DEBUG("RREQ target=%s src=%s dst=%s laddrs=%d\n",
		  print_ip(trg), print_ip(dp->src),
		  print_ip(dp->dst), DSR_RREQ_ADDRS_LEN(rreq_opt));

	/* Add reversed source route */
	// 翻转路径
	srt_rev = dsr_srt_new_rev(dp->srt);

	if (!srt_rev)
	{
		DEBUG("Could not reverse source route\n");
		return DSR_PKT_ERROR;
	}
	DEBUG("srt: %s\n", print_srt(dp->srt));
	DEBUG("srt_rev: %s\n", print_srt(srt_rev));
	// 将翻转路径 设置Timeout 信息 填入路由表中
	dsr_rtc_add(srt_rev, ConfValToUsecs(RouteCacheTimeout), 0);

	/* Set previous hop */
	// 如果有中间路径信息，则上一跳为翻转后第一项
	// 没有，则当前结点为正向第二个结点，上一跳就是翻转后的 dst
	if (srt_rev->laddrs > 0)
		dp->prv_hop = srt_rev->addrs[0];
	else
		dp->prv_hop = srt_rev->dst;
	// 因为 mac 地址每次转发都会改变，所以当前 mac 地址就是上一跳地址
	// neigh_tbl 邻居表中填入 上一跳 ip 和 mac 地址
	neigh_tbl_add(dp->prv_hop, dp->mac.ethh);

	/* Send buffered packets */
	// 通过翻转表项我们知道了到 srt_rev->dst 的路由信息，发送buffer中所有缓存的表项
	send_buf_set_verdict(SEND_BUF_SEND, srt_rev->dst);
	// 如果 rreq 报文的终点是自己， 那么给发端回复 rrep 报文
	if (rreq_opt->target == myaddr.s_addr)
	{
		DEBUG("RREQ OPT for me - Send RREP\n");

		/* According to the draft, the dest addr in the IP header must
		 * be updated with the target address */
#ifdef NS2
		dp->nh.iph->daddr() = (nsaddr_t)rreq_opt->target;
#else
		dp->nh.iph->daddr = rreq_opt->target;
#endif
		// 利用翻转路由表 发送 rrep 报文 dp->srt 只是填入 rrep 可选头更方便
		dsr_rrep_send(srt_rev, dp->srt);

		action = DSR_PKT_NONE;
		goto out;
	}

	/* 下面为转发处理的内容 */

	//  获取 rreq_opt 及该 rreq 报文经过的结点数目
	n = DSR_RREQ_ADDRS_LEN(rreq_opt) / sizeof(struct in_addr);
	// 如果自己rreq源端，抛弃包后直接退出 （因为 没有 路由路径，前面翻转后是 NULL）无需free
	if (dp->srt->src.s_addr == myaddr.s_addr)
		return DSR_PKT_DROP;
	// 如果自己在 rreq_opt 经过的路径里，（即自己曾经接受过报文）
	for (i = 0; i < n; i++)
		if (dp->srt->addrs[i].s_addr == myaddr.s_addr)
		{
			action = DSR_PKT_DROP;
			goto out;
		}

	/* TODO: Check Blacklist */
	// 找到 我->target 的路由路径
	srt_rc = lc_srt_find(myaddr, trg);

	if (srt_rc)
	{
		struct dsr_srt *srt_cat; // source cached route
		/* Send cached route reply */

		DEBUG("Send cached RREP\n");
		// 路由拼接 源->我 + 我-> 目标  = 源->目标
		srt_cat = dsr_srt_concatenate(dp->srt, srt_rc);

		FREE(srt_rc);

		if (!srt_cat)
		{
			DEBUG("Could not concatenate\n");
			goto rreq_forward;
		}

		DEBUG("srt_cat: %s\n", print_srt(srt_cat));
		// 查重，防止有巡回路径，如果有就转发 rreq
		if (dsr_srt_check_duplicate(srt_cat) > 0)
		{
			DEBUG("Duplicate address in source route!!!\n");
			FREE(srt_cat);
			goto rreq_forward;
		}
#ifdef NS2
		dp->nh.iph->daddr() = (nsaddr_t)rreq_opt->target;
#else
		dp->nh.iph->daddr = rreq_opt->target;
#endif
		DEBUG("Sending cached RREP to %s\n", print_ip(dp->src));
		// 利用拼接后的地址发送 rrep
		dsr_rrep_send(srt_rev, srt_cat);

		action = DSR_PKT_NONE;

		FREE(srt_cat);
	}
	else // 没有现成的路由路径，就继续转发
	{

	rreq_forward:
		dsr_pkt_alloc_opts_expand(dp, sizeof(struct in_addr));

		if (!DSR_LAST_OPT(dp, rreq_opt)) // 如果不是最后一个可选报文
		{
			char *to, *from;
			to = (char *)rreq_opt + rreq_opt->length + 2 +
				 sizeof(struct in_addr);
			from = (char *)rreq_opt + rreq_opt->length + 2;
			// memmove : 将 from 的前 in_addr 位移动到 to
			memmove(to, from, sizeof(struct in_addr));
		}
		// 更新 rreq_opt 的路由路径信息 和 长度
		rreq_opt->addrs[n] = myaddr.s_addr;
		rreq_opt->length += sizeof(struct in_addr);

		dp->dh.opth->p_len = htons(ntohs(dp->dh.opth->p_len) +
								   sizeof(struct in_addr));
#ifdef __KERNEL__
		dsr_build_ip(dp, dp->src, dp->dst, IP_HDR_LEN,
					 ntohs(dp->nh.iph->tot_len) +
						 sizeof(struct in_addr),
					 IPPROTO_DSR,
					 dp->nh.iph->ttl);
#endif
		/* Forward RREQ */
		action = DSR_PKT_FORWARD_RREQ;
		// 设置 action 后在上层函数 - dsr_io.c/dsr_recv() 中 XIMT 发送出去；
	}
out:
	FREE(srt_rev);
	return action;
}

#ifdef __KERNEL__

static int
rreq_tbl_proc_info(char *buffer, char **start, off_t offset, int length)
{
	int len;

	len = rreq_tbl_print(&rreq_tbl, buffer);

	*start = buffer + offset;
	len -= offset;
	if (len > length)
		len = length;
	else if (len < 0)
		len = 0;
	return len;
}

#endif /* __KERNEL__ */

int __init NSCLASS rreq_tbl_init(void)
{
	INIT_TBL(&rreq_tbl, RREQ_TBL_MAX_LEN);

#ifdef __KERNEL__
	proc_net_create(RREQ_TBL_PROC_NAME, 0, rreq_tbl_proc_info);
	get_random_bytes(&rreq_seqno, sizeof(unsigned int));
#else
	rreq_seqno = 0;
#endif
	return 0;
}

void __exit NSCLASS rreq_tbl_cleanup(void)
{
	struct rreq_tbl_entry *e;

	while ((e = (struct rreq_tbl_entry *)tbl_detach_first(&rreq_tbl)))
	{
		del_timer_sync(e->timer);
#ifdef NS2
		delete e->timer;
#else
		FREE(e->timer);
#endif
		tbl_flush(&e->rreq_id_tbl, crit_none);
	}
#ifdef __KERNEL__
	proc_net_remove(RREQ_TBL_PROC_NAME);
#endif
}
