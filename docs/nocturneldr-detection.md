# NocturneLdr 检测手册

> 配合 c2-signal v0.1.x 使用。本文档解释 `rules/yara/nocturne.yar` 与
> `rules/suricata/nocturneldr-payload.rules` 覆盖的攻击技术、误报控制策略、
> 以及如何在不接触真实样本的前提下验证规则。

## 1. 背景

[NocturneLdr](https://github.com/<upstream>) 是一个 Windows x64 shellcode
加载器,核心是把代码注入到某个已加载 DLL 的 `.text` section 缝隙里,并伪造
该 DLL 的 `RUNTIME_FUNCTION` 表项,让 Windows 解卷绕器、CET 影子栈、
WinDbg 等都以为那段代码是 DLL 自己的合法函数(BYOUD 技术)。在此基础上
它叠加了:

| 子技术 | 实现位置 | 检测面 |
|---|---|---|
| EAF 旁路(导出表过滤) | `Unguard.asm` | YARA / 行为侧 |
| Sleep 混淆(Zilean) | `Zilean.cpp` | 行为侧 / PCAP |
| 堆掩码 | `Zilean.cpp::MaskHeap` | 行为侧 |
| IAT 伪装 | `IatCamouflage.h` | YARA (PE 模块) |
| 编译期 API 哈希 | `Primitives.h` | YARA (DJB2 常量) |

PCAP 检测主要针对加载器**默认执行**的 msfvenom payload(`shell_reverse_tcp`
或 `meterpreter_reverse_https` 系列),不是加载器本身。

## 2. YARA 规则覆盖矩阵

| 规则 SID | 严重度 | 置信度 | 触发条件 | 适用制品 |
|---|---|---|---|---|
| `C2SIGNAL_NocturneLdr_Sample_HighConfidence` | critical | very_high | 默认 XOR key + 密文头 + 牺牲 DLL 字符串中 ≥ 2 项 | 任意 PE/二进制 |
| `C2SIGNAL_NocturneLdr_EAFBypass_ShieldedRead` | high | high | `ShieldedRead` 分发 + `MOV RAX,[RAX];RET` gadget | x64 PE |
| `C2SIGNAL_NocturneLdr_BYOUD_DynamicFunctionTableWalk` | high | high | 48B 范围内 `MOV RAX,[rip+disp]` + `LEA RCX,[rip+disp]` + `CMP [RAX],RCX` 三联 | x64 PE |
| `C2SIGNAL_NocturneLdr_SleepObfuscation_ROPChain` | high | high | MZ 头 + `CONTEXT_ALL = 0x0010000B` | x64 PE |
| `C2SIGNAL_NocturneLdr_HeapMasking_HeapWalk` | high | medium | `call+jz` 循环 + `rdrand eax` | x64 PE |
| `C2SIGNAL_NocturneLdr_DJB2_CompileTimeHashResolver` | medium | medium | 256B 内同现 5448 / shift 7 / 0x1337 XOR | x64 PE |
| `C2SIGNAL_NocturneLdr_IATCamouflage_USER32Only` | high | medium | 9 个 USER32 伪装 API 中 ≥ 7 + IAT 仅来自 USER32.dll | x64 PE(非 DLL) |
| `C2SIGNAL_NocturneLdr_Family_Master` | critical | high | 上述任一高置信组合 | x64 PE |

## 3. Suricata 规则覆盖矩阵

| SID | 触发 | 类型 | 误报风险 |
|---|---|---|---|
| `1000001` | HTTPS stage URI `/[A-Za-z0-9]{4,8}/` | verdict | 低(正常服务不会用单段随机字母 URI) |
| `1000002` | 出站 TCP 紧跟 `Microsoft Windows` 横幅 | verdict | 低(常见服务端口已排除) |
| `1000003` | 60 秒内首次高端口出站连接 | hunt | 中(普通用户行为也会触发) |
| `1000004` | UA 含 `Mozilla/5.0` + `Windows NT` + stage URI | verdict | 极低 |

## 4. 误报控制

* **`IATCamouflage_USER32Only`** — 对真实 GUI 程序会大量误报。**不要**对
  普通桌面应用跑这条,只在预过滤过的"可疑二进制"工作流里跑(例如 entropy > 7、
  缺失 Version Info、IAT 总数 < 15)。
* **`BYOUD_DynamicFunctionTableWalk`** — 三联模式对真实 JIT 引擎(RyuJIT、
  Chromium V8 TurboFan 桩)有理论命中可能。命中样本必须人工验证是否真的调用了
  `RtlAddFunctionTable`。
* **`ShellObfuscation_ROPChain`** — `CONTEXT_ALL = 0x0010000B` 是常量,
 单独出现可能误报,设计上是配合 MZ 头 + 文件大小 + `filesize < 5MB` 联合剪枝。

## 5. 验证(不接触真实样本)

c2-signal 仓库策略禁止提交真实样本,但规则可以通过**自造特征文件**验证:

### 5.1 YARA 规则验证

```bash
# 编译并自检(无命中)
yara -w rules/yara/nocturne.yar /dev/null

# 自造测试文件验证 Sample_HighConfidence
printf '\x37\xb6\x7c\xb2\x91\x5a\x49\x9f\x1a\x19' > /tmp/fake_xor_key.bin
yara -w rules/yara/nocturne.yar /tmp/fake_xor_key.bin
# 期望:命中 C2SIGNAL_NocturneLdr_Sample_HighConfidence
```

### 5.2 Suricata 规则验证

```bash
# 自造 stage URI HTTP 请求
printf 'GET /abcde/ HTTP/1.1\r\nHost: target\r\nUser-Agent: test\r\n\r\n' \
  > /tmp/payload.bin
suricata -r /tmp/payload.bin -S rules/suricata/nocturneldr-payload.rules \
  -l /tmp/suri-out/ -k none
grep "NOCTURNE" /tmp/suri-out/eve.json
```

## 6. 与其他检测面协同

| 攻击阶段 | 本规则集 | 建议的额外检测 |
|---|---|---|
| 投递(投递/下载) | — | EDR 文件落地告警、邮件网关 |
| 加载器启动 | `Sample_HighConfidence` | Sysmon Event ID 1 进程创建 |
| 注入到 windows.storage.dll | — | Sysmon Event ID 7(ImageLoad) |
| RUNTIME_FUNCTION 注入 | `BYOUD_DynamicFunctionTableWalk` | ETW `RtlAddFunctionTable` 调用 |
| Shellcode 执行 | `SleepObfuscation_ROPChain` | 调用栈完整性检查 |
| Sleep 混淆 | `HeapMasking_HeapWalk` | ETW 堆扫描告警 |
| Payload 出站 | `1000001 / 1000002 / 1000004` | DNS 日志、NetFlow |

## 7. 更新策略

* 当 NocturneLdr 上游发版、改变默认值(XOR key、密文头、IAT 列表)时,
  `Sample_HighConfidence` 规则需要更新;`Master` 规则会自动跟随。
* 当 YARA / Suricata 主版本升级时,验证 PE 模块与 `for any` 循环语法
  仍兼容。
