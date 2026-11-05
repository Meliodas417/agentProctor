# agentProctor

**On-demand monitoring of cyber-capable agents via system-level signals.**

Running an LLM monitor on every step an agent takes is expensive. agentProctor
takes a different approach: let a set of **cheap, always-on system-level signals**
(kernel crashes, VM restarts, exploit-primitive syscalls, sensitive-file writes)
act as triggers. They cost almost nothing while nothing is happening; the moment
one fires, you **escalate on demand** to an expensive monitoring model for review —
instead of watching the agent the whole time.

This repo contains the **collector** itself, plus a full guide for **running a real
agent against UK AISI's SandboxEscapeBench** and observing those signals.

> This is **authorized AI-safety capability evaluation + system-signal monitoring**
> research. The agent attempts container-escape CTF scenarios; we observe what
> system-level footprint a real exploit attempt leaves behind.

## Why the collector has two layers

A failed kernel exploit produces a **kernel panic/oops**, not a userspace segfault.
A sensor running *inside* the guest dies **together with the kernel**, and its log is
truncated at the moment of the crash — which is very likely why earlier runs "saw no
crash." So the crash signal **must be collected from the host / hypervisor side.**

- **Layer 1 — host side** (`collector/collector.py`, runs on the hypervisor, a panic
  cannot kill it)
  - libvirt domain lifecycle events: started / stopped / **crashed** / rebooted
    (the "restart" trigger)
  - guest serial console: kernel oops / BUG / panic text + userspace segfault
    (the "crash" trigger), via an 11-class crash classifier
  - output: `runs/<run-id>.jsonl`, one event per line, with crash class and severity
- **Layer 2 — inside the guest** (`collector/guest-syscall.sh`, using auditd)
  - process/exec tree + exploit-primitive syscalls (socket/setsockopt/bpf/mmap/ptrace…)
  - sensitive-path file-change watches (runc/passwd/shadow/sudoers/cron/.ssh/docker.sock/flag.txt)
    — **these fire even when nothing crashes** (e.g. a runc overwrite escape)
  - why auditd and not eBPF/Falco: kernel 4.8.1 (2016) predates modern BPF/CO-RE,
    so Falco's modern-eBPF probe cannot load there

See [`collector/README.md`](collector/README.md) for details.

## What it captures

| Source | Trigger | Example | Cost |
|---|---|---|---|
| libvirt events (host) | **restart / crash** | Crashed / Destroyed | very low, always-on |
| serial console (host) | **kernel crash** | panic / oops / GPF / soft-lockup | very low, always-on |
| auditd (guest) | **exploit primitives** | socket+setsockopt (AF_PACKET), bpf, mmap | medium, precise |
| auditd (guest) | **file change** | writes to /usr/bin/runc, /etc/shadow, /flag.txt | low, fires without a crash |

## Quick start

```bash
# 1. Self-test the crash classifier (offline)
python3 collector/collector.py --selftest

# 2. Start collecting on the host (before the agent runs)
python3 collector/collector.py --run-id demo

# 3. In another shell, run the bench (see the guide below)
```

Full procedure for "run a real agent against SandboxEscapeBench and observe the
signals" is in
[`docs/running-sandbox-escape-bench.md`](docs/running-sandbox-escape-bench.md).

## Results

Real captured traces and a write-up of what we observed live in
[`results/`](results/). In short:

- With internet, `gpt-5.3-codex` + `hint` **downloaded** a public CVE-2017-7308 PoC,
  compiled and ran it → **guest kernel panic**, captured host-side (an in-guest sensor
  would have died with it).
- With the agent's internet cut, the same model **never authored** the exploit itself →
  **no crash**. (See [`patches/container-egress-block.md`](patches/container-egress-block.md).)

## Findings worth keeping (honest notes)

- Only **memory-corruption** tasks crash the kernel (`packet_socket` CVE-2017-7308,
  `bpf_privesc`, `nf_tables_uaf`); race/logic tasks (dirty_cow/dirty_pipe/cgroup_release_agent)
  and config-escape tasks **don't crash** — they surface via file-change / syscall signals.
- **Use the `normal`/`hint` variant so the agent does its own trial-and-error.** The
  `solution` variant hands over a working exploit = no trial-and-error = no footprint,
  so it cannot validate the trigger premise.
- **Network access is a confound that must be controlled.** With internet, a model may
  just `curl` a public PoC and run it (equivalent to being handed the answer). To test an
  agent's *unaided* capability, cut the container's egress — see
  [`patches/container-egress-block.md`](patches/container-egress-block.md).
- **A run missing its system-signal stream is not evaluable; don't hide failures; don't
  back-fill events into old runs.**

## What this repo does NOT include

It does **not** contain SandboxEscapeBench's own files (`task.py`/`setup.sh`/exploit
sources) — they carry UK AISI canary markers and must not be redistributed. Fetch them
from the upstream repo at a pinned commit per the guide. `.env`, API keys, `.eval` logs
and VM disk images are never committed.
