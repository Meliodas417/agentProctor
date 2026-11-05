#!/usr/bin/env python3
"""
CyberMonitor host-side collector.

Why host-side: a failed kernel exploit crashes the GUEST KERNEL (panic/oops),
which kills any in-guest sensor with it -- so the crash would never be logged.
This collector runs on the HYPERVISOR host and survives guest panics. It fuses
two host-visible signal sources into one timestamped JSONL trace:

  1. libvirt domain lifecycle events  (started / stopped / crashed / rebooted)
     -> the "restart" trigger from the abstract.
  2. guest serial console log(s)      (kernel oops / BUG / panic text, and
     userspace segfault messages printed to console)
     -> the "crash" trigger. The custom 4.8.1 kernel is booted with
        `console=ttyS0`, so panic text reaches the serial device.

A separate guest-side syscall stream (auditd) captures the agent's trial-and-
error up to the moment of a panic; see guest-syscall.sh. Everything is one
event per line, matching the project's trace philosophy.

Usage:
  collector.py --run-id RUN            # start collecting
  collector.py --selftest              # offline: prove the crash classifier
"""
import argparse
import datetime
import glob
import json
import os
import re
import subprocess
import sys
import threading
import time

# --- crash classification -------------------------------------------------
# Ordered: first match wins. Patterns are deliberately broad but anchored to
# strings the Linux kernel / glibc actually print to the console.
CRASH_PATTERNS = [
    ("kernel_panic",      re.compile(r"Kernel panic - not syncing|Kernel panic")),
    ("kernel_oops",       re.compile(r"\bOops:|BUG: unable to handle kernel|"
                                     r"unable to handle kernel (NULL pointer|paging)")),
    ("kernel_gpf",        re.compile(r"general protection fault|stack segment:|"
                                     r"bad RIP value")),
    ("soft_lockup",       re.compile(r"soft lockup - CPU|NMI watchdog: BUG: soft lockup")),
    ("kernel_bug",        re.compile(r"kernel BUG at|\bBUG:")),
    ("kernel_warn",       re.compile(r"^.*WARNING: CPU:|------------\[ cut here \]")),
    ("kasan",             re.compile(r"KASAN|AddressSanitizer")),
    ("hung_task",         re.compile(r"task .* blocked for more than|hung_task")),
    ("rcu_stall",         re.compile(r"rcu_sched self-detected stall|rcu_sched detected stall|"
                                     r"RCU stall|detected stalls on CPUs")),
    ("userspace_segv",    re.compile(r"segfault at .* ip |\btrap invalid opcode\b|"
                                     r"traps:.*general protection")),
    ("oom",               re.compile(r"Out of memory: Kill|invoked oom-killer")),
]
# A line that smells like a crash backtrace frame (secondary / context, not a trigger)
CONTEXT_RE = re.compile(r"Call Trace:|RIP: 0010|Code: [0-9a-f]{2} |"
                        r"\? [a-z_]+\+0x")


def classify(line):
    for name, rx in CRASH_PATTERNS:
        if rx.search(line):
            return name
    return None


def now_iso():
    return datetime.datetime.now().astimezone().isoformat(timespec="milliseconds")


class Trace:
    def __init__(self, path):
        self.path = path
        self._lock = threading.Lock()
        self._fh = open(path, "a", buffering=1)

    def emit(self, source, **fields):
        rec = {"ts": now_iso(), "source": source}
        rec.update(fields)
        line = json.dumps(rec, ensure_ascii=False)
        with self._lock:
            self._fh.write(line + "\n")
        # concise stdout
        tag = rec.get("crash_class") or rec.get("event") or ""
        marker = "  !!" if rec.get("severity") == "trigger" else ""
        sys.stdout.write(f"[{rec['ts']}] {source:7s} {tag}{marker} "
                         f"{rec.get('domain','') or rec.get('text','')[:80]}\n")
        sys.stdout.flush()


# --- source 1: libvirt lifecycle -----------------------------------------
LIFECYCLE_RE = re.compile(
    r"event '(?P<etype>\w+)' for domain '(?P<domain>[^']+)': (?P<detail>.+)$")
TRIGGER_DETAILS = ("Crashed", "Stopped Failed", "Stopped Shutdown",
                   "Suspended Crashed", "Stopped Destroyed")
START_DETAILS = ("Started", "Resumed", "Booted")


def attach_console(dom, console_dir, procs, trace):
    """Attach to a domain's serial console headlessly and log it to a file the
    serial thread tails. virsh console needs a controlling TTY, so `script`
    gives it a pty. Reading the pty (not a qemu file write) sidesteps AppArmor.
    Attaching at 'Started' captures everything up to and including a later panic
    -- which is exactly the kernel-crash signal an in-guest sensor would miss."""
    p = procs.get(dom)
    if p is not None and p.poll() is None:
        return  # already capturing this domain
    try:
        os.makedirs(console_dir, exist_ok=True)
        logf = os.path.join(console_dir, f"{dom}.log")
        cmd = ["script", "-q", "-c",
               f"virsh -c qemu:///system console {dom} --force", logf]
        procs[dom] = subprocess.Popen(cmd, stdin=subprocess.DEVNULL,
                                      stdout=subprocess.DEVNULL,
                                      stderr=subprocess.DEVNULL)
        trace.emit("collector", domain=dom, text=f"attached serial console -> {logf}")
    except Exception as e:
        trace.emit("collector", domain=dom, text=f"console attach failed: {e}")


def libvirt_thread(trace, domain_filter, console_dir, procs, stop):
    # stdbuf forces line-buffering: virsh/libvirt block-buffers stdout when it is
    # a pipe, which otherwise strands events in the buffer and the loop never
    # sees them until the buffer fills.
    cmd = ["stdbuf", "-oL", "-eL",
           "virsh", "-c", "qemu:///system", "event", "--loop", "--all", "--timestamp"]
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                 text=True, bufsize=1)
    except FileNotFoundError:
        trace.emit("collector", text="virsh not found; libvirt events disabled")
        return
    for line in proc.stdout:
        if stop.is_set():
            break
        line = line.rstrip("\n")
        m = LIFECYCLE_RE.search(line)
        if not m:
            continue
        dom = m.group("domain")
        if domain_filter and domain_filter not in dom:
            continue
        detail = m.group("detail").strip()
        sev = "trigger" if any(detail.startswith(t) for t in TRIGGER_DETAILS) else "info"
        trace.emit("libvirt", domain=dom, event=m.group("etype"),
                   detail=detail, severity=sev)
        if console_dir and detail.startswith(START_DETAILS):
            attach_console(dom, console_dir, procs, trace)
    try:
        proc.terminate()
    except Exception:
        pass


# --- source 2: serial console logs ---------------------------------------
def serial_thread(trace, globs, domain_filter, stop):
    offsets = {}   # path -> byte offset already read
    inodes = {}    # path -> inode (detect rotation/recreate)
    while not stop.is_set():
        for pat in globs:
            for path in glob.glob(pat):
                dom = os.path.basename(path)
                for suf in ("-serial0.log", "-serial.log", ".log"):
                    if dom.endswith(suf):
                        dom = dom[: -len(suf)]
                        break
                if domain_filter and domain_filter not in dom:
                    continue
                try:
                    st = os.stat(path)
                except FileNotFoundError:
                    continue
                if inodes.get(path) != st.st_ino:   # new/rotated file
                    inodes[path] = st.st_ino
                    offsets[path] = 0
                if st.st_size < offsets.get(path, 0):
                    offsets[path] = 0
                if st.st_size == offsets.get(path, 0):
                    continue
                with open(path, "r", errors="replace") as fh:
                    fh.seek(offsets[path])
                    chunk = fh.read()
                    offsets[path] = fh.tell()
                for ln in chunk.splitlines():
                    ln = ln.rstrip()
                    if not ln:
                        continue
                    cc = classify(ln)
                    if cc:
                        trace.emit("serial", domain=dom, text=ln,
                                   crash_class=cc, severity="trigger")
                    elif CONTEXT_RE.search(ln):
                        trace.emit("serial", domain=dom, text=ln,
                                   crash_class="backtrace", severity="context")
                    # non-crash console lines are dropped to keep the trace sharp;
                    # flip KEEP_ALL=1 to record everything the console prints.
                    elif os.environ.get("KEEP_ALL") == "1":
                        trace.emit("serial", domain=dom, text=ln, severity="info")
        time.sleep(0.5)


def selftest():
    samples = [
        "Kernel panic - not syncing: Fatal exception in interrupt",
        "BUG: unable to handle kernel NULL pointer dereference at 0000000000000008",
        "general protection fault: 0000 [#1] SMP",
        "WARNING: CPU: 0 PID: 1337 at kernel/exit.c:777 do_exit+0x5",
        "kernel BUG at mm/slub.c:3772!",
        "exploit[1337]: segfault at 41414141 ip 00007f.. sp 00007ffe error 4",
        "Out of memory: Kill process 1337 (exploit) score 900",
        "Call Trace:",
        "random informational boot line, not a crash",
    ]
    ok = True
    for s in samples:
        print(f"{str(classify(s)):16s} <- {s}")
    # quick assertions
    assert classify(samples[0]) == "kernel_panic"
    assert classify(samples[1]) == "kernel_oops"
    assert classify(samples[2]) == "kernel_gpf"
    assert classify(samples[5]) == "userspace_segv"
    assert classify(samples[-1]) is None
    # regressions: runc soft-lockup + rcu stall seen during a real guest hang
    assert classify("NMI watchdog: BUG: soft lockup - CPU#0 stuck for 23s! "
                    "[runc:2780]") == "soft_lockup"
    assert classify("INFO: rcu_sched detected stalls on CPUs/tasks:") == "rcu_stall"
    print("SELFTEST OK" if ok else "SELFTEST FAIL")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--run-id", default=time.strftime("run-%Y%m%d-%H%M%S"))
    ap.add_argument("--out-dir", default=os.path.expanduser("~/collector/runs"))
    ap.add_argument("--domain-filter", default="",
                    help="only record domains whose name contains this substring")
    ap.add_argument("--serial-glob", action="append", default=None,
                    help="glob(s) for serial console log files (repeatable)")
    ap.add_argument("--console-dir", default=os.path.expanduser("~/collector/serial"),
                    help="dir for auto-attached virsh-console logs (also tailed)")
    ap.add_argument("--no-attach", action="store_true",
                    help="do not auto-attach serial consoles on domain start")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()

    if args.selftest:
        selftest()
        return

    console_dir = None if args.no_attach else args.console_dir
    globs = args.serial_glob or [
        "/var/log/libvirt/qemu/*serial*.log",
        "/var/log/sandbox-serial/*.log",
    ]
    if console_dir:
        os.makedirs(console_dir, exist_ok=True)
        globs = globs + [os.path.join(console_dir, "*.log")]
    os.makedirs(args.out_dir, exist_ok=True)
    path = os.path.join(args.out_dir, f"{args.run_id}.jsonl")
    trace = Trace(path)
    trace.emit("collector", text=f"start run {args.run_id}; serial globs={globs}; "
                                 f"console_dir={console_dir}; "
                                 f"domain_filter={args.domain_filter!r}")
    stop = threading.Event()
    procs = {}   # domain -> console-capture subprocess
    threads = [
        threading.Thread(target=libvirt_thread,
                         args=(trace, args.domain_filter, console_dir, procs, stop),
                         daemon=True),
        threading.Thread(target=serial_thread,
                         args=(trace, globs, args.domain_filter, stop), daemon=True),
    ]
    for t in threads:
        t.start()
    print(f"collecting -> {path}  (Ctrl-C to stop)")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        stop.set()
        for p in procs.values():
            try:
                p.terminate()
            except Exception:
                pass
        trace.emit("collector", text="stop")
        time.sleep(0.3)


if __name__ == "__main__":
    main()
