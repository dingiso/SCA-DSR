int NSCLASS dsr_xxx_send(/*报文可选的参数，控制报文的具体结构*/)
{
    /*初始化 pkt,buf,len */
    struct dsr_pkt *dp = NULL;
    char *buf;
    int len;
    // 开辟报文空间
    dp = dsr_pkt_alloc(NULL);

    /* 基本必有得报文的初始化，源地址目的地址等 */
    dp->src = my_addr();
    dp->dst = srt->dst;

    len =                                  // 根据不同报文设置需要的长度
        buf = dsr_pkt_alloc_opts(dp, len); // 利用len开辟空间付给buf

    dp->nh.iph = dsr_build_ip // 初始化ip头

        /* 下面为很多的重复过程 */
        buf += DSR_XXX_LEN;
    len -= DSR_XXX_LEN;

    dp->xxx = dsr_xxx_opt_add(); // 利用参数初始化该报文断结构
    /* 重复过程的结尾 */

    XMIT(dp); // 发送报文
}

int NSCLASS dsr_xxx_opt_recv(dsr_pkt *dp, struct dsr_xxx_opt, *xxx_opt)
{
    /* 判断报文是否已经接收 */
    if (!dp || !xxx_opt || dp->flags & PKT_PROMISC_RECV)
        return DSR_PKT_ERROR;
    /* 判断报文的正确性 */
    if (dp->num_xxx_opts < MAX_xx_OPTS)
        dp->xxx_opt[dp->num_xxx_opts++] = xxx_opt;
    else
        return DSR_PKT_ERROR;
    /* 修改报文内容 */
    // 例：
    dp->xxx_opts[/* 最后一位*/] = my_addrs();

    /* 利用报文内容修改自己的状态路由表等 */
    // 例：
    xxx_tbl_route_discovery_cancel(dst);

    /* 判断是否转发 ，并转发 */
    if (dp->dst.s_addr == myaddr.s_addr)
    {
        return DSR_PKT_SEND_BUFFERED;
    }
    /* Forward */
    return DSR_PKT_FORWARD;
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

    /* Add reversed source route */
    // 翻转路径
    srt_rev = dsr_srt_new_rev(dp->srt);

    if (!srt_rev)
    {
        DEBUG("Could not reverse source route\n");
        return DSR_PKT_ERROR;
    }

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
        dp->nh.iph->daddr = rreq_opt->target;
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

        // 查重，防止有巡回路径，如果有就转发 rreq
        if (dsr_srt_check_duplicate(srt_cat) > 0)
        {
            DEBUG("Duplicate address in source route!!!\n");
            FREE(srt_cat);
            goto rreq_forward;
        }

        dp->nh.iph->daddr = rreq_opt->target;
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

        /* Forward RREQ */
        action = DSR_PKT_FORWARD_RREQ;
        // 设置 action 后在上层函数 - dsr_io.c/dsr_recv() 中 XIMT 发送出去；
    }
out:
    FREE(srt_rev);
    return action;
}

int NSCLASS dsr_rrep_send(struct dsr_srt *srt, struct dsr_srt *srt_to_me)
{
    struct dsr_pkt *dp = NULL;
    char *buf;
    int len, ttl, n;
    // 参数为空 ，返回 -1
    if (!srt || !srt_to_me)
        return -1;

    dp = dsr_pkt_alloc(NULL);

    if (!dp)
    {
        DEBUG("Could not allocate DSR packet\n");
        return -1;
    }
    // RREP报文地址  我的地址 -> 给我发rreq的地址
    dp->src = my_addr();
    dp->dst = srt->dst;
    // 没有中间结点，下一跳为 dst ，否则就是路由表第一项
    if (srt->laddrs == 0)
        dp->nxt_hop = dp->dst;
    else
        dp->nxt_hop = srt->addrs[0];

    len = DSR_OPT_HDR_LEN + DSR_SRT_OPT_LEN(srt) +
          DSR_RREP_OPT_LEN(srt_to_me) /*  + DSR_OPT_PAD1_LEN */;
    // 获取中间结点个数
    n = srt->laddrs / sizeof(struct in_addr);

    // 设置 TTL 值，如果按 srt 转发需要 n+1 次，防止报文在节点间错误的转发引起拥塞
    ttl = n + 1;

    DEBUG("TTL=%d, n=%d\n", ttl, n);
    // 申请 RREP_OPT 空间
    buf = dsr_pkt_alloc_opts(dp, len);

    if (!buf)
        goto out_err;
    // 组建 IP 头
    dp->nh.iph = dsr_build_ip(dp, dp->src, dp->dst, IP_HDR_LEN,
                              IP_HDR_LEN + len, IPPROTO_DSR, ttl);

    if (!dp->nh.iph)
    {
        DEBUG("Could not create IP header\n");
        goto out_err;
    }
    // 组件 DSR options 头
    dp->dh.opth = dsr_opt_hdr_add(buf, len, DSR_NO_NEXT_HDR_TYPE);

    if (!dp->dh.opth)
    {
        DEBUG("Could not create DSR options header\n");
        goto out_err;
    }
    // 进行 路由选项头部的构建
    buf += DSR_OPT_HDR_LEN; // 移动指针
    len -= DSR_OPT_HDR_LEN;

    /* Add the source route option to the packet */
    dp->srt_opt = dsr_srt_opt_add(buf, len, 0, dp->salvage, srt);

    if (!dp->srt_opt)
    {
        DEBUG("Could not create Source Route option header\n");
        goto out_err;
    }
    // 进行 RREP 选项头部的构造
    buf += DSR_SRT_OPT_LEN(srt); // 移动指针
    len -= DSR_SRT_OPT_LEN(srt);

    dp->rrep_opt[dp->num_rrep_opts++] =
        dsr_rrep_opt_add(buf, len, srt_to_me);

    if (!dp->rrep_opt[dp->num_rrep_opts - 1])
    {
        DEBUG("Could not create RREP option header\n");
        goto out_err;
    }

    dp->flags |= PKT_XMIT_JITTER;
    // 发送报文
    XMIT(dp);

    return 0;
out_err:
    if (dp)
        dsr_pkt_free(dp);

    return -1;
}