# 更新日志

本项目的重要变更记录在此文件中。

## [Unreleased]

### 新增

- NocturneLdr 专项 YARA 规则(`rules/yara/nocturne.yar`):
  覆盖 BYOUD 动态函数表注入、EAF 旁路(ShieldedRead)、RtlRegisterWait + NtContinue
  Sleep 混淆链(Zilean)、HeapWalk 堆掩码、DJB2 编译期哈希解析器、USER32-only IAT
  伪装六大技术点,并提供 `C2SIGNAL_NocturneLdr_Family_Master` 总规则作为高置信
  报警入口。每条规则附带 MITRE ATT&CK 映射、严重度与置信度元数据。

### 文档

- README(中/英)在检测路由表中增加 NocturneLdr 行,指向新规则文件。
- `rules/suricata/nocturneldr-payload.rules`(4 条 Suricata 规则)针对 NocturneLdr 默认执行的 msfvenom payload 的网络侧特征:stage URI、shell banner、high-port 出站、reverse_https 默认 UA。所有规则使用 `NOCTURNE` 前缀和 `mitre` 元数据,便于 SOC 分诊。
- `docs/nocturneldr-detection.md` 检测手册:覆盖矩阵、误报控制、验证食谱、不接触样本的自检方法,以及与其他检测面(Sysmon/ETW)的协同建议。
- `testdata/nocturneldr-strings.txt` 纯文本 fixture:列出 `nocturne.yar` 引用的字节序列与字符串,供本地与 CI 自检,**不包含任何可执行样本**。
- `.github/workflows/rules.yml` PR 校验:在 `rules/**` 与 `docs/nocturneldr-detection.md` 变更时自动跑 YARA 编译与 Suricata `-T` 语法校验。

## [0.1.0] - 2026-07-04

首次公开版本。

### 新增

- 基于 Go API 与 Next.js 静态前端的 Docker 化检测工作台。
- 按制品类型路由至 YARA、Chainsaw/Sigma 或 Suricata。
- Cobalt Strike Beacon、BOF 与解码配置专项 YARA 检测。
- 异步扫描、持久化历史记录、结果查看与删除。
- YARA 命中规则源文件查看及精确行号定位。
- 本地 YARA 新建、编辑、校验、启用、停用与热重载。
- 固定版本的可选社区规则拉取脚本。
- 中文默认文档、英文文档、实际运行界面截图与 MIT 许可证。
