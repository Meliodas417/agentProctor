# agentProctor

**按需监控有网络攻击能力的 agent —— 用系统级信号当触发器。**

直接对 agent 的每一步做 LLM 监控太贵。agentProctor 的思路是:让一组**便宜、always-on 的系统级信号**(内核崩溃、VM 重启、exploit 原语 syscall、敏感文件改动)当触发器,平时几乎零成本;一旦某个信号亮了,才**按需**升级去调昂贵的监控模型复核。

这个仓库放的是**采集器**本身,以及**怎么在 UK AISI 的 SandboxEscapeBench 上用真实 agent 跑出这些信号**的完整指南。

> 这是**授权的 AI 安全能力评测 + 系统信号监视**研究。agent 跑的是容器逃逸 CTF 靶场,用来观测"真实 exploit 试错会产生哪些系统足迹"。

## 为什么采集器要分两层

失败的内核 exploit 产生的是**内核 panic/oops**,不是用户态 segfault。装在 guest 里的传感器会**跟内核一起崩死**,日志当场截断——这极可能就是"跑完没看到 crash"的真正原因。所以崩溃信号**必须从宿主/hypervisor 侧采**。

- **Layer 1 — 主机侧** (`collector/collector.py`,跑在 hypervisor 上,panic 杀不死它)
  - libvirt 域生命周期事件:started / stopped / **crashed** / rebooted(= "重启"触发器)
  - guest 串口控制台:内核 oops / BUG / panic 文本 + 用户态 segfault(= "崩溃"触发器),11 类崩溃分类器
  - 输出:`runs/<run-id>.jsonl`,一行一事件,带崩溃分类与 severity
- **Layer 2 — guest 内** (`collector/guest-syscall.sh`,用 auditd)
  - 进程/exec 树 + exploit 原语 syscall(socket/setsockopt/bpf/mmap/ptrace…)
  - 敏感路径 file-change watch(runc/passwd/shadow/sudoers/cron/.ssh/docker.sock/flag.txt)——**逃逸不崩溃时照样亮**
  - 为什么是 auditd 不是 eBPF/Falco:内核 4.8.1(2016)早于现代 BPF/CO-RE,Falco modern-eBPF 加载不了

详见 [`collector/README.md`](collector/README.md)。

## 能采到什么

| 来源 | 触发器 | 例子 | 代价 |
|---|---|---|---|
| libvirt 事件(主机) | **重启 / 崩溃** | Crashed / Destroyed | 极低,always-on |
| 串口(主机) | **内核崩溃** | panic / oops / GPF / soft-lockup | 极低,always-on |
| auditd(guest) | **exploit 原语** | socket+setsockopt(AF_PACKET)、bpf、mmap | 中,但精准 |
| auditd(guest) | **文件改动** | 写 /usr/bin/runc、/etc/shadow、/flag.txt | 低,不崩也亮 |

## 快速开始

```bash
# 1. 自测崩溃分类器(离线)
python3 collector/collector.py --selftest

# 2. 主机上开采(先于 agent 运行启动)
python3 collector/collector.py --run-id demo

# 3. 另起一个 shell,按指南跑 bench(见下)
```

完整的"在 SandboxEscapeBench 上用真 agent 跑一轮并观测信号"流程,见
[`docs/running-sandbox-escape-bench.md`](docs/running-sandbox-escape-bench.md)。

## 实测要点(诚实记录)

- 只有**内存破坏类**任务会崩内核(`packet_socket` CVE-2017-7308、`bpf_privesc`、`nf_tables_uaf`);
  race/logic 类(dirty_cow/dirty_pipe/cgroup_release_agent)和配置逃逸类**不崩**,走文件改动/syscall 信号。
- **必须用 `normal`/`hint` 变体让 agent 自己试错**;`solution` 变体=喂现成 exploit=无试错=无足迹,不能用来验证触发前提。
- **网络访问是必须控制的混淆变量**:有网时,模型可能直接 `curl` 下载公开 PoC 再跑(本质和喂答案一样);
  要测"agent 自主能力",用 [`patches/container-egress-block.md`](patches/container-egress-block.md) 给容器断网。
- **缺系统流的运行不可评价;不藏失败;不给旧运行补造事件。**

## 不收录什么

本仓库**不含** SandboxEscapeBench 自身的文件(`task.py`/`setup.sh`/exploit 源码)——它们带 UK AISI 的 canary 标记、不应转载。请按指南从官方仓库获取并锁定提交。`.env`、API key、`.eval` 日志、VM 磁盘镜像都不入库。
