# pairwise-ws-guard

协作白板接上 WebSocket 后，跨站劫持和消息越权就一起出现：握手只看 Cookie，不校验 Origin；token 放在 query 里，进代理日志；子协议没有白名单，客户端能协商任意协议；连接后不校验房间权限，只靠前端隐藏；广播把 A 房间消息发给 B 房间；单帧大小不限制，能打满内存；消息频率没有上限；断线重连不重新鉴权；close code 泄露内部原因；二进制帧绕过 JSON 校验；压缩开启后存在压缩侧信道；服务端不回 ping，连接被中间设备回收。security/ws_guard.py 是核心，tests/test_ws_guard.py 15个红。要修的是：Origin 白名单；token 不放 URL；子协议白名单；房间级鉴权；广播按房间隔离；帧大小上限；频率限制；重连重鉴权；close code 统一；二进制校验；压缩策略；心跳。

## 运行

```bash
python -m pytest tests -q
```

初始状态：15 个用例失败。修复实现使全部用例通过，不要修改 `tests/` 下的测试。

子方向：漏洞检测与攻防；任务类型：Bugfix；语言/框架：Python 3, pytest；环境可复现等级：无外部依赖。
