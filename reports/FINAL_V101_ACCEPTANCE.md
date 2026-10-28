# 第三轮发布前验收 — C

起点：a4847a3e358f386bceb6f08107948a81ea492438。继续独立改进分支。

## 已有修复评审

计数器规则顺序、prio严格整数/0、查询namespace及进程失败时die的行为，经Python/Bash离线测试独立通过。回归测试放在原V1.0本地临时导出中实际失败，证明能够暴露旧行为。Bash部分模型/源码文本检查不能证明整个生命周期；实际保护函数使用命令替身测试，无真实ip、nft或拓扑操作。

清理按项目锁、状态归属、inode与进程保护检查；失败后保留状态并尝试标记FAILED；已删除的部分资源不会自动重建。项目锁不能防止其他特权进程在检查与删除之间竞争，离线测试不能证明无误删/残留。真实清理、部分创建/删除、信号中断及回滚均NOT RUN，是发布前安全门槛。

## 本轮发现与修复

C-R3-001，P2 Confirmed/FIXED：V0.7两项离线check_plan及V0.6 make_report仍使用assert检查外部计划/CSV，-O下会漏掉不一致并输出/生成PASS。用临时合成错误计划和不完整/错误分组CSV新增4项失败回归，在-O下4项均失败（旧行为没有拒绝）。改为显式ValueError后通过，不改变合法输入行为。

V0.6正常CLI原本先verify_saved，再make_report；verify_saved已经显式核验日志哈希/CSV。此次属于报告函数及诊断的补强，不证明历史发布结果存在错误。只用真实保存数据读取并把旧/新报告都写入TemporaryDirectory，生成内容完全相同。原始报告、JSON/CSV/PCAP及所有哈希清单未变。V0.7真实测量代码/流量/目标未改变，若后续使用新源码root staging，必须另行审核哈希，未自动部署。

自测/只读诊断中仍有历史assert，例如V0.9 self_test；不将-O下这些自测打印的PASS作为独立验证依据。被维护的生产输入/策略/完整性校验用显式异常；优化模式unittest实际调用函数并验证失败行为。

## 结果与历史FAIL诊断

原31项、-O31项及27 Bash检查再次PASS；新增4项后35/35、-O35/35 PASS。工作流8个run步骤全部在本地3.12普通用户环境成功执行。两项合法计划额外-O默认检查PASS，无探针。V0.6保存证据、V0.7 24指标及V0.9 15项哈希PASS。新兼容验证器仍确认7项历史源码pin及保存18案例。

空JSON是真实失败尝试，不只是版本兼容问题：0字节仍不能解析，FAIL保留并证明与V1.0逐字节不变。旧release收尾工具--check本轮仍实际FAIL，原因是历史源码pin；它还绑定旧HEAD/main/干净状态。没有修改旧pin、清单、工具或降低校验。当前程序的18成功案例PASS与上述FAIL分别报告。

v1.0.0 Annotated Tag及原main未动，正式GitHub Release按用户独立确认保留。CI为push/pull_request/workflow_dispatch、contents只读，fetch-depth:0满足历史读取；无pull_request_target/secrets/事件文本shell注入，没有真实网络实验或Root配置。云端Actions/3.11实际运行NOT RUN，3.11语法检查PASS不冒充运行结果。

## 决策

CONDITIONALLY READY：可进入GitHub PR/CI阶段，不建议现在直接发布v1.0.1。最终SHA的双版本CI、代码评审，以及授权隔离VM中的真实清理故障路径验证完成后再发布。离线测试没有完成实际Root安全控制验收。未Root部署、真实清理、nftables修改或远程写入。
