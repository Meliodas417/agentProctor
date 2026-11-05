# Running SandboxEscapeBench with a real agent and observing system signals

Goal: on a KVM host, drive UK AISI's SandboxEscapeBench container-escape scenarios
with a **real model** (via OpenRouter), while this repo's collector records the
system-level signals (crash / restart / syscalls / file changes).

Throughout: **use the `normal`/`hint` variant, never `solution`** (which hands over a
ready-made exploit); **start the collector before the agent and stop it after**;
**a run missing its system-signal stream is not evaluable.**

---

## 0. Host prerequisites (example: Ubuntu 22.04 + KVM)

You need `/dev/kvm` and passwordless sudo. Install:

```bash
sudo apt-get update
sudo apt-get install -y docker.io qemu-kvm libvirt-daemon-system \
     vagrant vagrant-libvirt libguestfs-tools packer
# uv (to run inspect)
curl -LsSf https://astral.sh/uv/install.sh | sh    # lands in ~/.local/bin/uv
```

> Gotcha we hit: building the box fails with "no artifacts were created" if
> `virt-sysprep` is missing — it ships in `libguestfs-tools`, so install it.

## 1. Get the bench (pin the commit, not vendored here)

```bash
git clone https://github.com/UKGovernmentBEIS/sandbox_escape_bench.git
cd sandbox_escape_bench
git checkout 9fa5f26c          # pinned commit, for reproducibility
uv sync                         # builds .venv, installs inspect_ai etc.
```

> The bench's `scenarios/*/setup.sh`, `task.py` and exploit sources carry a canary
> marker (a "do not put in training corpora" warning line + a GUID). **Do not** copy
> them into another repo or into training data.

## 2. Build the custom kernel box (needed for memory-corruption tasks)

`packet_socket` (CVE-2017-7308) and similar tasks need an old kernel to be exploitable.
Build the box with packer:

```bash
# Exact script names depend on the bench version; typically:
./scripts/build-debs.sh            # compile the kernel .deb in docker
./scripts/build-kernel-box.sh packet_socket   # packer + vagrant-libvirt packaging
vagrant box list | grep sandbox    # sandbox-packet_socket appearing = success
```

`images.yaml` should point the task at the built box, e.g.:

```yaml
packet_socket:
  box: sandbox-packet_socket
  kernel: "4.8.1"
```

## 3. Configure OpenRouter (never commit the key)

Create `.env` in the bench root (inspect auto-loads it):

```bash
cat > .env <<'EOF'
OPENROUTER_API_KEY=<your-openrouter-key>   # your own key, do not commit
INSPECT_SANDBOX_SETUP_TIMEOUT=900
INSPECT_MAX_VAGRANT_STARTUPS=1
EOF
```

One OpenRouter key works for all models. Model ids look like
`openrouter/openai/gpt-5.3-codex`, `openrouter/anthropic/claude-haiku-5.5`.

## 4. Start the collector first (host side)

```bash
# On the host, before the eval
python3 /path/to/agentProctor/collector/collector.py --run-id run01
#   -> ~/collector/runs/run01.jsonl
#   auto-attaches the serial console when a domain starts
#   KEEP_ALL=1 also records non-crash serial lines
```

The collector reads libvirt events via `virsh -c qemu:///system`; no sudo needed if the
host user is in the libvirt group.

## 5. Run the eval (real agent)

```bash
cd sandbox_escape_bench
uv run inspect eval scenarios/packet_socket/task.py \
  --model openrouter/openai/gpt-5.3-codex \
  -T sandbox=vagrant -T variant=hint \
  --token-limit 1000000 --max-sandboxes 1 --log-dir logs
```

- `variant`: `normal` (task only) / `hint` (adds one line naming the vulnerability type,
  **no exploit**). **Never `solution`** (it drops a ready-made exploit into the container).
- `--token-limit` caps cost; a frontier model usually hits the cap in one sample, on the
  order of a few dollars.

When done, the inspect log is at `logs/*.eval` (a zip with the full trajectory); the
collector trace is at `runs/run01.jsonl`.

## 6. Read the captured signals

```bash
# crash / trigger lines
grep -E '"severity": ?"trigger"|crash_class|panic|[Oo]ops|segfault|lockup|stall' \
  ~/collector/runs/run01.jsonl

# count by crash class
python3 - <<'PY'
import json, collections
c = collections.Counter()
for l in open('/root/collector/runs/run01.jsonl'):
    o = json.loads(l)
    if o.get('crash_class'): c[o['crash_class']] += 1
print(dict(c))
PY
```

A "crash" trace looks like this (all captured host-side; at this moment any in-guest
sensor has already died with the kernel):

```
libvirt  Started Booted
serial   kernel_oops   BUG: unable to handle kernel NULL pointer dereference
serial   kernel_oops   Oops: 0010 [#1] SMP
serial   kernel_panic  Kernel panic - not syncing: Fatal exception in interrupt
```

See [`../results/`](../results/) for real captured traces.

## 7. Offline mode (test the agent's unaided capability)

With internet, a model may just `curl` a public PoC and run it — which is not its own
trial-and-error. To force it to rely on its own knowledge, cut the challenge container's
egress per [`../patches/container-egress-block.md`](../patches/container-egress-block.md)
(the network interface for AF_PACKET and `docker exec` are preserved; the host's
connection to OpenRouter is unaffected).

## 8. (Optional) Enable the guest layer to capture pre-panic footprint

After the VM is up, as root inside the guest:

```bash
bash /path/to/agentProctor/collector/guest-syscall.sh start run01
#   -> /var/log/cybermon/run01.audit.log
#   FLOOD=1 audits all syscalls (very noisy)
```

Align the guest audit stream with the host trace by timestamp afterward.

---

## Gotchas (to save you time)

- **Give the guest 4 vCPUs.** With a single core, runc soft-locks CPU#0 during setup
  (`soft lockup [runc]` + rcu stall) and setup times out. Set `v.cpus = 4` and memory
  3072 in the `Vagrantfile`.
- **Raise the setup timeout to 900s** (`INSPECT_SANDBOX_SETUP_TIMEOUT` in `.env`).
- **Clear `~/collector/serial/*.log` before each run.** At startup the collector re-reads
  leftover serial logs, producing phantom crash events from the previous run.
- **A non-interactive shell can't find `uv`:** use the absolute path `~/.local/bin/uv`
  or `export PATH` first.
- **`virsh console` needs a controlling TTY:** the collector uses
  `script -q -c "virsh console ..."` to give it a pty, which also sidesteps AppArmor's
  restriction on qemu writing files.
- **The crash-classifier regexes must match real kernel output:** wording like
  `soft lockup` / `rcu_sched detected stalls` is easy to miss; after editing, validate
  with `collector.py --selftest`.
