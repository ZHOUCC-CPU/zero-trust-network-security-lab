# Post V1 quality audit — 项目 C

审计日期：2026-10-28。结论 PARTIAL：本地离线修复和证据复核通过；Root staged 实验 NOT RUN。无已证实 P0。

## 基线

原 main / HEAD `15470fc9b1e44016565b9a08a2a5123e6ff133bb` 与指定正式版基线一致；初始工作区干净。origin `https://github.com/ZHOUCC-CPU/zero-trust-network-security-lab.git`。v1.0.0 Tag 对象 `4a6bb5d00b8b2c081e3f00ea5f0db0e3bbcf0464` 解引用即上述 HEAD；RC Tag 保留。新分支 `improve/post-v1-quality-audit`，main/Tag 未移动，无推送/Release 操作。

## 发现

### C-001 — P1 — Confirmed，已修复

- Project：C；位置：`scripts/v08_counter_parser.py:69-104`。
- Technical explanation：解析器验证四条规则集合，却忽略 nftables 的有序语义及 chain priority。
- Impact：终止 drop 移到前面后，允许流量不再可达，旧解析器仍接受；错误 priority 的快照也被接受。
- Evidence：test_drop_first_rejected、test_return_rule_last_rejected、test_wrong_priority_rejected 在修复前均失败（旧实现没有抛异常）。
- Fix：按 EXPECTED 顺序逐条验证，要求 forward priority=0。保持原 default-deny、协议/IP/接口/端口匹配及非负整数计数器检查。
- Verification：8个新增解析/增量测试通过，含正常策略、规则乱序、错误 priority、bool counter、计数器增长/回退及畸形文档。保存 V0.8 的18案例仍通过严格检查。

### C-002 — P1 — Confirmed，已修复（运行环境验证仍 NOT RUN）

- Project：C；位置：`scripts/topology_down.sh` verify_namespace()。
- Technical explanation：`[[ -z "$(ip netns pids ...)" ]]` 只检查输出长度；命令失败且无输出会被视为无进程。
- Impact：无法检查进程时仍可能进入 namespace 删除流程，破坏原先的 fail-closed 安全边界。
- Evidence：只提取该函数，通过 Bash 函数替身模拟 ns_exists/stat/ip；旧实现中 ip 返回7且空输出时 guard 返回0，回归失败。没有 source/执行拓扑脚本或调用真实 ip。
- Fix：先检查 pids 查询退出状态，失败则 die，再核验列表为空。
- Verification：3个实际函数逻辑测试通过（空列表允许、有进程拒绝、查询失败拒绝），全脚本 bash -n 通过。真实 namespace 生命周期、清理中断与回滚 NOT RUN。

### C-003 — P2 — Confirmed，已修复

- Project：C；位置：原无 `.github/workflows`，现 `.github/workflows/offline.yml`。
- Technical explanation：原有安全离线测试未接入 CI；缺乏跨版本回归。
- Impact：维护中策略解析、安全保护逻辑退化不易及时发现。
- Evidence：初始仓库无 CI；已有10 Python、27 Bash逻辑检查。
- Fix：新增 Python3.11/3.12只读工作流，执行 unittest、Bash语法、Python/JSON结构、明确列出的 --check/--self-test、保存 V0.8 证据检查。无新增依赖。
- Verification：本机3.12执行所有对应安全检查；3.11与 GitHub 云端 NOT RUN。CI没有sudo、--execute、拓扑或防火墙命令。不是以通配方式运行实验脚本。

## 历史证据及限制（非新造缺陷）

- `evidence/v08_runs/snapshot_b4FUqJXy/gateway_forward.nft.json` 为0字节：全仓JSON扫描 FAIL；`reports/V0.8_EXPERIMENT_REPORT.md:44` 已说明保留失败空快照。它不属于成功的18案例 session；保持原样，不作为成功样本，不改变清单或原报告。
- `scripts/v08_finish_release.py --check` FAIL：源码 SHA-256 mismatch；该历史收尾工具还绑定旧 HEAD `97f3ef3`、main和干净状态。没有更新历史批准哈希、放宽分支保护或运行 --execute。维护验证改用独立的只读解析/证据命令；历史工具不能作为本分支总体 PASS 门槛。
- topology_up/down、load_v04_policy、check_topology、测试流量脚本仅审查或 bash -n，未执行。up 有锁、身份标记、失败回滚；down 检查 inode和进程后删除；仍须授权环境测试并发、部分创建/删除与信号中断。Bash旧测试部分复制了模型，新增测试直接提取实际保护函数以降低漂移风险。
- nftables策略只在网关 namespace 的 forward hook 生效，default drop，允许两条固定TCP新连接，已有 established/related 可通过；不是用户身份认证或生产零信任系统。加载前已有连接可能通过 established 规则；应在受控干净连接跟踪状态验证，不能从计数器单独推出ALLOW/DENY。
- V0.6固定6情景、3+3轮；V0.7仅两允许流、每流30 TCP connect探针、有界iperf3，CPU/内存是WSL guest整体而非规则独占成本。无真实生产性能泛化。V0.8增量不能证明流归属；V0.9只读完整性与历史哈希不等于本机无残留，live --check 未运行。

## 测试结果

|检查|结果|
|---|---|
|修改前 Python|10/10 PASS|
|修改前 Bash 逻辑|27/27 PASS|
|新解析回归在旧实现|8项中3 FAIL、5 PASS|
|新清理回归在旧实现|3项中1 FAIL、2 PASS|
|修改后 Python|21/21 PASS；新增11|
|修改后优化模式|21/21 PASS|
|修改后 Bash 逻辑|27/27 PASS|
|安全现有检查/自测命令|12/12 exit0，具体见下|
|V0.6保存日志/CSV/哈希复核|PASS|
|V0.7保存指标日志/CSV/哈希复核|24/24 PASS|
|V0.8保存证据|18/18案例 PASS，含manifest/JSON/CSV/计数器|
|V0.9 manifest.sha256|15/15 PASS|
|Bash语法|9脚本 PASS|
|全仓JSON扫描|119合法，1历史空文件 FAIL（保留）|
|ShellCheck|NOT RUN：未安装|
|历史发布收尾检查|FAIL：历史锁定源码不匹配，未绕过|

12项命令：v06_compare --check；v07_benchmark_orchestrator --check；v07_tcp_latency（默认检查）；v07_iperf3_throughput（默认检查）；v07_resource_metrics（默认只读 /proc 检查）；v08_counter_parser --self-test；v08_counter_delta --self-test；v08_evidence_validator --self-test / --check-plan；v08_live_snapshot --check；v08_root_audit_case --check；v09_resource_integrity --self-test。所有Python命令设置 PYTHONDONTWRITEBYTECODE=1。合成自测数据不表述为真实实验。

修改/新增6文件：`scripts/v08_counter_parser.py`、`scripts/topology_down.sh`、`tests/test_counter_policy.py`、`tests/test_cleanup_guard.py`、`.github/workflows/offline.yml`、本报告。无原始证据变更；git diff --check PASS。新CI的JSON扫描仅验证源码/测试配置，不将已注明的历史失败快照伪装为合法证据。

## 下一维护版本

可进入v1.0.1候选审查；发布前需3.11/3.12云端CI和独立审核。若声称清理运行行为已修复并验证，必须在另获授权的隔离Linux VM测试pids命令失败、进程存在、部分清理与信号异常。当前仅验证安全保护函数逻辑，不得宣称真实Root实验通过。所有网络/防火墙/Root staged执行均NOT RUN；无历史版本覆盖。

远端只读核实尝试：`gh run list --repo ZHOUCC-CPU/zero-trust-network-security-lab --limit 1 --json conclusion,status,headSha,url,createdAt` 失败（error connecting to api.github.com）；最新云端CI状态 BLOCKED。A 的 git ls-remote --tags 亦因 github.com DNS 失败，无法确认远端 Tag。未尝试提升网络权限。
