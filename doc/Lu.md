# 卢睿博的分析记录

| 英文缩写 | 中文全称                          |
| -------- | --------------------------------- |
| RREQ     | 路由发现请求消息(routing request) |
| RREP     | 路由请求回应消息(routing reply)   |
|          |                                   |
|          |                                   |

### Search Diary

下面为探寻过程中不明白而写的查询笔记：

`struct timeval` : 包含从Epoch到创建结构体时所经过的时间（秒.微秒 的小数形式）

`TimerHandler` : NS2网络模拟中提供的一种计时器，在对应时间进行操作

`GFP_ATOMIC` : 用来从中断处理和进程上下文之外的其他代码中分配内存. 从不睡眠.

### `dsr_rreq_route_discovery`

发现到 **target** 的路由 成功返回**1** ，已经寻找了返回**0**， 建立表项内存不足返回 `-ENOMEM`

将 **target** 作为表项 填入(或"移到") `rreq_tabl` 的最后一个，判断是否寻找过 **target** ，如果没有就设置表项的相关状态，设置一个定时器，最后将 **target** 交给 `dsr_rreq_send` 函数构建 **packet** 并发送。

小 tips :

`timeval_add_usecs` 函数注意**timeval**格式为 **秒.微秒** 的小数形式 

