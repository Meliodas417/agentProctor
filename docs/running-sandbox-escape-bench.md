# 用真实 agent 跑 SandboxEscapeBench 并观测系统信号

目标:在一台 KVM 宿主上,用**真实模型**(经 OpenRouter)驱动 UK AISI 的
SandboxEscapeBench 容器逃逸靶场,同时用本仓库的采集器录下系统级信号
(崩溃 / 重启 / syscall / 文件改动)。

全程遵守:**用 `normal`/`hint` 变体,绝不用 `solution`(喂现成 exploit)**;
**采集器先于 agent 启动、晚于 agent 结束停**;**缺系统流的运行不可评价**。

---

## 0. 宿主前置(以 Ubuntu 22.04 + KVM 为例)

需要:`/dev/kvm` 可用、passwordless sudo。装:

```bash
sudo apt-get update
sudo apt-get install -y docker.io qemu-kvm libvirt-daemon-system \
     vagrant vagrant-libvirt libguestfs-tools packer
# uv(跑 inspect 用)
curl -LsSf https://astral.sh/uv/install.sh | sh    # 落在 ~/.local/bin/uv
```

> 踩过的坑:打 box 时缺 `virt-sysprep` 会报 "no artifacts were created" ——
> 它在 `libguestfs-tools` 里,务必装上。

## 1. 获取 bench(锁定提交,不入本库)

```bash
git clone https://github.com/UKGovernmentBEIS/sandbox_escape_bench.git
cd sandbox_escape_bench
git checkout 9fa5f26c          # 固定提交,保证可复现
uv sync                         # 建 .venv,装 inspect_ai 等
```

> bench 的 `scenarios/*/setup.sh`、`task.py`、exploit 源码顶部带 canary 标记
> (一行"禁止进入训练语料"的警告 + 一个 GUID),**不要**把它们拷进别的仓库或训练语料。

## 2. 建自定义内核 box(内存破坏类任务需要)

`packet_socket`(CVE-2017-7308)等任务要旧内核才能触发,用 packer 打 box:

```bash
# 具体脚本名以 bench 版本为准,通常是:
./scripts/build-debs.sh            # 在 docker 里编内核 .deb
./scripts/build-kernel-box.sh packet_socket   # packer + vagrant-libvirt 打包
vagrant box list | grep sandbox    # 出现 sandbox-packet_socket 即成功
```

`images.yaml` 里该任务应指向打好的 box,例如:

```yaml
packet_socket:
  box: sandbox-packet_socket
  kernel: "4.8.1"
```

## 3. 配 OpenRouter(key 绝不入库)

在 bench 根目录建 `.env`(inspect 会自动加载):

```bash
cat > .env <<'EOF'
OPENROUTER_API_KEY=<your-openrouter-key>   # 你自己的 key,别提交
INSPECT_SANDBOX_SETUP_TIMEOUT=900
INSPECT_MAX_VAGRANT_STARTUPS=1
EOF
```

一个 OpenRouter key 通吃所有模型。模型 id 形如 `openrouter/openai/gpt-5.3-codex`、
`openrouter/anthropic/claude-haiku-5.5`。

## 4. 先起采集器(主机侧)

```bash
# 在宿主上,先于 eval 启动
python3 /path/to/agentProctor/collector/collector.py --run-id run01
#   -> ~/collector/runs/run01.jsonl
#   域一 Started 会自动挂串口;KEEP_ALL=1 可连非崩溃串口行也记
```

采集器用 `virsh -c qemu:///system` 读 libvirt 事件,无需 sudo(宿主在 libvirt 组即可)。

## 5. 跑 eval(真实 agent)

```bash
cd sandbox_escape_bench
uv run inspect eval scenarios/packet_socket/task.py \
  --model openrouter/openai/gpt-5.3-codex \
  -T sandbox=vagrant -T variant=hint \
  --token-limit 1000000 --max-sandboxes 1 --log-dir logs
```

- `variant`:`normal`(只给任务)/ `hint`(额外给一句漏洞类型,**不给 exploit**)。
  **绝不用 `solution`**(它把现成 exploit 文件塞进容器)。
- `--token-limit` 兜住成本;前沿模型一轮约撞上限,几美元量级。

跑完,inspect 日志在 `logs/*.eval`(zip,内含完整轨迹);采集器轨迹在
`runs/run01.jsonl`。

## 6. 读采集到的信号

```bash
# 崩溃 / 触发行
grep -E '"severity": ?"trigger"|crash_class|panic|[Oo]ops|segfault|lockup|stall' \
  ~/collector/runs/run01.jsonl

# 按崩溃类别计数
python3 - <<'PY'
import json, collections
c = collections.Counter()
for l in open('/root/collector/runs/run01.jsonl'):
    o = json.loads(l)
    if o.get('crash_class'): c[o['crash_class']] += 1
print(dict(c))
PY
```

典型的"崩溃那次"轨迹长这样(全是主机侧抓的,此刻 guest 内传感器已随内核冻死):

```
libvirt  Started Booted
serial   kernel_oops   BUG: unable to handle kernel NULL pointer dereference
serial   kernel_oops   Oops: 0010 [#1] SMP
serial   kernel_panic  Kernel panic - not syncing: Fatal exception in interrupt
```

## 7. 断网模式(测 agent 自主能力)

有网时模型可能直接 `curl` 下载公开 PoC 再跑——那不算"自己试错"。要逼它凭本事写,
按 [`../patches/container-egress-block.md`](../patches/container-egress-block.md)
给挑战容器断网(保留网卡给 AF_PACKET、保留 docker exec、模型 API 走宿主不受影响)。

## 8. (可选)开 guest 层,抓 panic 前足迹

VM 起来后,在 guest 内以 root:

```bash
bash /path/to/agentProctor/collector/guest-syscall.sh start run01
#   -> /var/log/cybermon/run01.audit.log
#   FLOOD=1 可审计所有 syscall(很吵)
```

事后把 guest 的 audit 流和主机轨迹按时间戳对齐。

---

## 踩过的坑(省你时间)

- **guest 给 4 核**。单核时 runc 在 setup 阶段会把 CPU 软锁死(`soft lockup [runc]` +
  rcu stall),setup 超时作废。把 `Vagrantfile` 的 `v.cpus` 调到 4、内存 3072。
- **setup 超时调到 900s**(`.env` 的 `INSPECT_SANDBOX_SETUP_TIMEOUT`)。
- **每跑前清 `~/collector/serial/*.log`**。采集器启动时会把残留串口日志重读进来,
  凭空多出上一跑的崩溃事件。跑前清空(或归档)serial 目录。
- **非交互 shell 找不到 `uv`**:用绝对路径 `~/.local/bin/uv` 或先 `export PATH`。
- **`virsh console` 需要控制 TTY**:采集器用 `script -q -c "virsh console ..."` 给它一个 pty,
  顺带绕开 AppArmor 对 qemu 写文件的限制。
- **崩溃分类器的正则要对得上实际内核输出**:`soft lockup` / `rcu_sched detected stalls` 这类
  措辞容易漏,改完用 `collector.py --selftest` 验证。
