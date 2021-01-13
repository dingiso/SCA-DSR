/* Copyright (C) Uppsala University
 *
 * This file is distributed under the terms of the GNU general Public
 * License (GPL), see the file LICENSE
 *
 * Author: Erik Nordström, <erikn@it.uu.se>
 */
#ifdef __KERNEL__
#include "dsr-dev.h"
#endif

#ifdef NS2
#include "ns-agent.h"
#endif

#include "dsr.h"
#include "dsr-rerr.h"
#include "dsr-opt.h"
#include "debug.h"
#include "dsr-srt.h"
#include "dsr-ack.h"
#include "link-cache.h"
#include "maint-buf.h"

static struct dsr_rerr_opt *dsr_rerr_opt_add(char *buf, int len,
											 int err_type,
											 struct in_addr err_src,
											 struct in_addr err_dst,
											 struct in_addr unreach_addr,
											 int salv)
{
	struct dsr_rerr_opt *rerr_opt;

	if (!buf || len < (int)DSR_RERR_HDR_LEN)
		return NULL;

	rerr_opt = (struct dsr_rerr_opt *)buf;

	rerr_opt->type = DSR_OPT_RERR;
	rerr_opt->length = DSR_RERR_OPT_LEN;
	rerr_opt->err_type = err_type;
	rerr_opt->err_src = err_src.s_addr;
	rerr_opt->err_dst = err_dst.s_addr;
	rerr_opt->res = 0;
	rerr_opt->salv = salv;

	switch (err_type)
	{
	case NODE_UNREACHABLE:
		if (len < (int)(DSR_RERR_HDR_LEN + sizeof(struct in_addr)))
			return NULL;
		rerr_opt->length += sizeof(struct in_addr);
		memcpy(rerr_opt->info, &unreach_addr, sizeof(struct in_addr));
		break;
	case FLOW_STATE_NOT_SUPPORTED:
		break;
	case OPTION_NOT_SUPPORTED:
		break;
	}

	return rerr_opt;
}
// 组装 rerr 报文并发送， dp_trigg 是出现错误的报文 ， unr_addr 是出现错误的结点的地址
int NSCLASS dsr_rerr_send(struct dsr_pkt *dp_trigg, struct in_addr unr_addr)
{
	struct dsr_pkt *dp;
	struct dsr_rerr_opt *rerr_opt;
	struct in_addr dst, err_src, err_dst, myaddr;
	char *buf;
	int n, len, i;

	myaddr = my_addr();
	// src 地址不能是自己，如果是自己就不用发送 rerr 了
	if (!dp_trigg || dp_trigg->src.s_addr == myaddr.s_addr)
		return -1;
	// 没有路由信息
	if (!dp_trigg->srt_opt)
	{
		DEBUG("Could not find source route option\n");
		return -1;
	}
	// 如果该结点未被救助过，则返回 src 源节点，如果被救助过，选择救助结点为目标结点及 addrs[1]
	if (dp_trigg->srt_opt->salv == 0)
		dst = dp_trigg->src;
	else
		dst.s_addr = dp_trigg->srt_opt->addrs[1];

	dp = dsr_pkt_alloc(NULL);

	if (!dp)
	{
		DEBUG("Could not allocate DSR packet\n");
		return -1;
	}
	// 查找路由路径
	dp->srt = dsr_rtc_find(myaddr, dst);

	if (!dp->srt)
	{
		DEBUG("No source route to %s\n", print_ip(dst));
		return -1;
	}

	len = DSR_OPT_HDR_LEN + DSR_SRT_OPT_LEN(dp->srt) +
		  (DSR_RERR_HDR_LEN + 4) +
		  DSR_ACK_HDR_LEN * dp_trigg->num_ack_opts;

	/* Also count in RERR opts in trigger packet */
	for (i = 0; i < dp_trigg->num_rerr_opts; i++)
	{
		if (dp_trigg->rerr_opt[i]->salv > ConfVal(MAX_SALVAGE_COUNT))
			break;

		len += (dp_trigg->rerr_opt[i]->length + 2);
	}
	// 成功计算总长度
	DEBUG("opt_len=%d SR: %s\n", len, print_srt(dp->srt));
	// laddrs 是以 bytes 数的地址长度，除以每个地址字节数，得到中间地址数目
	n = dp->srt->laddrs / sizeof(struct in_addr);
	dp->src = myaddr;
	dp->dst = dst;
	dp->nxt_hop = dsr_srt_next_hop(dp->srt, n);
	// 构建 IP 头
	dp->nh.iph = dsr_build_ip(dp, dp->src, dp->dst, IP_HDR_LEN,
							  IP_HDR_LEN + len, IPPROTO_DSR, IPDEFTTL);

	if (!dp->nh.iph)
	{
		DEBUG("Could not create IP header\n");
		goto out_err;
	}

	buf = dsr_pkt_alloc_opts(dp, len);

	if (!buf)
		goto out_err;
	// 构建 DSR options header ,rerr 不包含下一个头部了
	dp->dh.opth = dsr_opt_hdr_add(buf, len, DSR_NO_NEXT_HDR_TYPE);

	if (!dp->dh.opth)
	{
		DEBUG("Could not create DSR options header\n");
		goto out_err;
	}
	// 构建 路由可选头部 Source Route option header
	buf += DSR_OPT_HDR_LEN;
	len -= DSR_OPT_HDR_LEN;

	dp->srt_opt = dsr_srt_opt_add(buf, len, 0, 0, dp->srt);

	if (!dp->srt_opt)
	{
		DEBUG("Could not create Source Route option header\n");
		goto out_err;
	}
	// 构建 rerr 可选头部 RRER option header
	buf += DSR_SRT_OPT_LEN(dp->srt);
	len -= DSR_SRT_OPT_LEN(dp->srt);

	rerr_opt = dsr_rerr_opt_add(buf, len, NODE_UNREACHABLE, dp->src,
								dp->dst, unr_addr,
								dp_trigg->srt_opt->salv);

	if (!rerr_opt)
		goto out_err;
	// 填入报文中原有的旧的 rrer_opt
	buf += (rerr_opt->length + 2);
	len -= (rerr_opt->length + 2);

	/* Add old RERR options */
	for (i = 0; i < dp_trigg->num_rerr_opts; i++)
	{
		// 如果该 rerr 被救助太多次
		if (dp_trigg->rerr_opt[i]->salv > ConfVal(MAX_SALVAGE_COUNT))
			break;

		memcpy(buf, dp_trigg->rerr_opt[i],
			   dp_trigg->rerr_opt[i]->length + 2);

		len -= (dp_trigg->rerr_opt[i]->length + 2);
		buf += (dp_trigg->rerr_opt[i]->length + 2);
	}

	/* TODO: Must preserve order of RERR and ACK options from triggering
	 * packet */
	// 填入报文中原有的旧的 ack_opt
	/* Add old ACK options */
	for (i = 0; i < dp_trigg->num_ack_opts; i++)
	{
		memcpy(buf, dp_trigg->ack_opt[i],
			   dp_trigg->ack_opt[i]->length + 2);

		len -= (dp_trigg->ack_opt[i]->length + 2);
		buf += (dp_trigg->ack_opt[i]->length + 2);
	}

	err_src.s_addr = rerr_opt->err_src;
	err_dst.s_addr = rerr_opt->err_dst;

	DEBUG("Send RERR err_src %s err_dst %s unr_dst %s\n",
		  print_ip(err_src),
		  print_ip(err_dst),
		  print_ip(*((struct in_addr *)rerr_opt->info)));

	XMIT(dp);

	return 0;

out_err:

	dsr_pkt_free(dp);

	return -1;
}
// 接收 rerr
int NSCLASS dsr_rerr_opt_recv(struct dsr_pkt *dp, struct dsr_rerr_opt *rerr_opt)
{
	struct in_addr err_src, err_dst, unr_addr;
	// unr 是坏结点的具体 ip 地址
	if (!rerr_opt)
		return -1;
	// 填入 dp 报文的 rrer_opt
	dp->rerr_opt[dp->num_rerr_opts++] = rerr_opt;

	switch (rerr_opt->err_type)
	{
	case NODE_UNREACHABLE:
		err_src.s_addr = rerr_opt->err_src;
		err_dst.s_addr = rerr_opt->err_dst;
		// 将 info 的地址 复制到 unr
		memcpy(&unr_addr, rerr_opt->info, sizeof(struct in_addr));

		DEBUG("NODE_UNREACHABLE err_src=%s err_dst=%s unr=%s\n",
			  print_ip(err_src), print_ip(err_dst), print_ip(unr_addr));

		/* For now we drop all unacked packets... should probably
		 * salvage */
		maint_buf_del_all(err_dst);

		/* Remove broken link from cache */
		lc_link_del(err_src, unr_addr);

		/* TODO: Check options following the RERR option */
		/* 		dsr_rtc_del(my_addr(), err_dst); */
		// 未实现的删除路由缓存
		break;
	case FLOW_STATE_NOT_SUPPORTED:
		DEBUG("FLOW_STATE_NOT_SUPPORTED\n");
		break;
	case OPTION_NOT_SUPPORTED:
		DEBUG("OPTION_NOT_SUPPORTED\n");
		break;
	}

	return 0;
}
