# 卢睿博的分析记录

| 英文缩写 | 中文全称                          |
| -------- | --------------------------------- |
| RREQ     | 路由发现请求消息(routing request) |
| RREP     | 路由请求回应消息(routing reply)   |
| RERR     | 路由错误(routing error reply)   |
| ACK      | 流模式确认消息                   |

### 分析函数过程

`dsr_rreq_route_discovery` **&** `dsr_rreq_opt_recv` 发送和处理请求报文
`dsr_rrep_send` **&** `dsr_rrep_opt_recv` 发送和处理回应报文
`dsr_rerr_send` 错误处理

### Search Diary

下面为探寻过程中不明白而写的查询笔记：

`struct timeval` : 包含从Epoch到创建结构体时所经过的时间（秒.微秒 的小数形式）

`TimerHandler` : NS2网络模拟中提供的一种计时器，在对应时间进行操作

`GFP_ATOMIC` : 用来从中断处理和进程上下文之外的其他代码中分配内存. 从不睡眠.



`memmove(dst,src,num)` : 将 **src** 地址的前 **num** 位移动到 **dst**
`memcpy (dst,src,num)` : 将 **src** 地址的前 **num** 位复制到 **dst**
## RREQ

### `dsr_rreq_route_discovery`

更多是发送前的判定部分

发现到 **target** 的路由 成功返回**1** ，已经寻找了返回**0**， 建立表项内存不足返回 `-ENOMEM`

将 **target** 作为表项 填入(或"移到") `rreq_tabl` 的最后一个，判断是否寻找过 **target** ，如果没有就设置表项的相关状态，设置一个定时器，最后将 **target** 交给 `dsr_rreq_send` 函数构建 **packet** 并发送。

#### 小 tips :

`timeval_add_usecs` 函数注意**timeval**格式为 **秒.微秒** 的小数形式 


### `dsr_rreq_send`

构建 `rreq` 报文，并通过广播的方式发送出去

### `dsr_rreq_opt_recv`

接受 rreq 报文 处理并选择回复或转发
调用函数时，顺便发送 `send_buf` 中到源结点的报文，相当于一个阻塞点，因为**DSR**是利用广播的方式进行发送的，所以有足够的结点调用此函数并清空buffer。但是这个逻辑可以在思考一下。
#### 接收后的动作选择：
回复 rrep ： 是rreq的终点 ， 或者路由表中有 自己到终点的路径（不含重复路径）
转发 ： 不是终点 也 无路径
抛弃 ： 出现错误或冗余
#### 返回值：
1. DSR_PKT_NONE ：过程中已经发送过 rrep 报文而不需要上层函数再发送返回此值 - 自己是rreq终点或有 我->终点 路由缓存 返回
2. DSR_PKT_ERROR ：出现错误时返回 - 多个 rreq_opt， 未成功提取到 rreq_opt ，或未成功翻转为 srt_rev （ 路径为空
3. DSR_PKT_DROP  ：已经接收过该报文，报文被丢弃
4. DSR_PKT_FORWARD_RREQ ：需要进行转发，由上层函数负责转发
#### tips:
* 逻辑顺序可以调整， rreq_tbl 中有表项和 出现再 rreq_opt.addrs[] 中是一个意思
`neigh_tbl_add` : 中第二个参数就是报文中 mac 地址，因为 mac 地址每次转发都改成自己的地址

### `dsr_opt_recv`


当接收到 `dsr_pkt` 报文时，可选头部是储存在 `dh.raw` 下的，是一种 `char*` 原始数据，需要通过一个转换函数 `DSR_GET_OPT` 将其提取出来，转换为 `dsr_opt` 数据结构

## RREP

### `dsr_rrep_opt_recv`

**tips:**
`DSR_RREP_ADDRS_LEN`: 返回值 是 长度 - （struct）in_addr

## RERR




## Packet Salvaging 路由救助
如果该结点转发时（包中的路由路径所指示的）下一跳坏了，那么 该节点可选择另一条路径发送，且该行为是有限度的,通常为路由表项的个数

## ACK
当 DSR 处于 流模式 时

以下是我个人在分析过程中觉得实际代码中存在的问题：
1.	Dsr_rerr_opt_recv 函数中，接收了 RERR 报文后未转发，可能导致链路错误未成功通知到路径上的每一个结点
