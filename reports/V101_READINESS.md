# 第二轮 V1.0.1 候选复核 — C

基于 `6c28c5bdb2ed751ecc3ed1b7534b066ad2fd2d49`，原21 Python测试、优化模式21项及27 Bash逻辑检查再次PASS。v1.0.0 annotated Tag解引用 `15470fc9b1e44016565b9a08a2a5123e6ff133bb`，是改进分支祖先，main/Tag未移动。

## 新边界缺陷及修复

- C-R2-001，P1 Confirmed：priority=False因Python相等语义被当作0。新增失败回归后要求prio严格为int；规则顺序、固定匹配、default-drop和计数器条件不放宽。
- C-R2-002，P1 Confirmed：topology_down的ns_exists把`ip netns list`失败和资源不存在混淆，异常清理时可能跳过资源检查并删除状态。函数替身回归复现旧版返回普通不存在状态；现在先检查列表命令成功，否则die。只接受成功查询证明不存在，awk精确匹配并避免早退管道歧义。
- 原进程查询失败保护独立重跑PASS。测试只提取实际ns_exists/verify_namespace并以Bash函数替身mock ip/stat，未source或执行拓扑脚本，未调用真实ip。

新增10测试：priority1、namespace查询3、兼容验证6。总31/31 PASS，优化模式31/31 PASS，Bash27/27 PASS。Bash9脚本语法、20个Python AST和3个配置JSON检查PASS，git diff --check PASS。

## 历史与当前验证分离

新增 `scripts/verify_v101_compatibility.py`：只读git取固定V1.0提交，检查annotated Tag和7项历史源码哈希；ast.literal_eval读取历史FILES清单，不执行历史Python或发布工具。分别报告历史integrity与当前源码匹配旧pin的结果，再用当前严格验证器核实保存的18案例。

历史 `evidence/v08_runs/snapshot_b4FUqJXy/gateway_forward.nft.json` 为0字节，不能解析JSON，仍为FAIL。旧报告已说明为失败尝试；新验证器确认该文件与V1.0逐字节一致并标记preserved=true，不把它算作成功证据。

旧 `v08_finish_release.py --check` 本轮仍实际FAIL（source SHA-256 mismatch），还绑定旧HEAD97f3ef3/main/干净状态。没有更新旧pin或绕过保护。新验证器退出0只表示分离检查完成，不表示历史失败快照或旧release工具通过；输出保留独立FAIL/NOT RUN字段。

## 本机结果及候选

12项原安全check/self-test全部exit0；V0.6保存证据PASS，V0.7保存24指标PASS。兼容验证：7项历史源码完整性PASS；当前程序18案例PASS；历史空快照FAIL且未变；当前parser匹配旧源码pin FAIL（预期版本不兼容）。V0.9清单15/15哈希PASS，全部原清单未变。

CI新增只读兼容命令，并设置checkout fetch-depth:0以读取历史Tag/源码，普通runner即可运行，无sudo/真实探针/拓扑或防火墙命令。YAML和8个run块Bash语法PASS；Python3.11及云端NOT RUN。

离线候选检查PASS，完整运行环境验收PARTIAL。真实namespace生命周期、并发/信号中断、部分清理、错误查询和进程占用的Root staged验证NOT RUN，需另获授权在隔离VM实施。inode/锁及再次检查降低误删风险，离线函数测试不证明不存在TOCTOU或特权外部进程竞争。未执行topology_up/down、nftables修改或任何Root网络实验；无历史证据/Tag/Release修改。
