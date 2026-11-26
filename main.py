"""crowdstrike-processes — what is running on every fleet host, over RTR.

Name, pid, parent, owner, start time, image path and — the one that matters —
the **full command line**.

It owns no credentials. Auth and the host list come from the ``crowdstrike``
capability; this module only knows how to ask a host what it is running.

Why the command line
--------------------
A process called ``powershell.exe`` says nothing. Its arguments say everything:
whether it is a scheduled maintenance script or a base64 blob piped from the
internet. Falcon's own process telemetry is event-shaped — it tells you what
started — whereas this is the table as it stands right now, which is the question
asked during triage.

How it gets there
-----------------
An RTR session **per host** and one ``runscript`` for its platform, printing one
process per line. One session per host rather than one batch across many is the
point of the screen: a batch returns when its slowest member does, while here
each host lands on its own and can be opened while the rest are still going.

Read-only. The process table is read; nothing is started, stopped or signalled.

What it reads
-------------
* **Windows** — ``Win32_Process``, which carries the command line and the parent
  that ``Get-Process`` does not. The owner is a separate call per process, so it
  is asked for only while the host is not too busy for it to be worth the time —
  a list without owners beats a scan that times out and returns nothing.
* **Linux / macOS** — ``ps`` with an explicit output format, so what comes back
  does not depend on which ``ps`` the distribution ships.

The parent's *name* is resolved here rather than on the endpoint, which would
need the whole table before it could answer. ``ppid 4812`` tells you nothing;
``4812 explorer.exe`` tells you somebody double-clicked, and ``4812 winword.exe``
tells you a document did.

Methods
-------
  ui              -> the screen: fetch hosts, tick them, scan
  fetch           -> load the reachable inventory from ``crowdstrike``
  scan_selected   -> enumerate the ticked hosts
  scan_all        -> enumerate every listed host
  progress        -> one tick of the progress loop
  stop            -> call off what has not started
  open_host       -> one host's processes, in a tab (the double-click target)
  about           -> one process, in a tab
  processes       -> the same data as JSON, for other modules
  make_report     -> the last scan, or one host of it, handed to a report provider
"""

import json
import os
import queue
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

from limen_sdk import (
    Button,
    Catalog,
    Checkbox,
    Label,
    MenuItem,
    Module,
    Row,
    Separator,
    Table,
    Text,
    Window,
)

# The module's own strings. `host.locale()` is asked per render rather than
# once at start: the language is the application's setting and can change
# while the module is running.
CAT = Catalog.from_dir(os.path.dirname(os.path.abspath(__file__)), ("en", "uk"))
_lang = {"code": "en"}


def t(key, **args):
    """Translate for the language the host last reported."""
    return CAT.tr(_lang["code"], key, **args)


def _sync_locale():
    """Re-read the host's language before drawing.

    Asked each time rather than once at start, because it is the
    application's setting and the user can change it while the module is
    open. One round-trip per render, which is what the Rust modules do too.
    """
    try:
        _lang["code"] = m.host.locale()
    except Exception:  # noqa: BLE001
        pass  # keep the last language rather than failing to draw


CAP = "crowdstrike.processes"
m = Module("crowdstrike-processes", [CAP])

# The fetched inventory. Held so reopening the tab restores the list rather than
# re-querying the fleet.
_hosts = {"rows": None}
_status = {"msg": ""}

# Per-host scan state, the only thing shared between the worker threads and the
# dispatch thread — so every read and write of it takes `_lock`.
#
#   _jobs[host_id] = {hostname, platform, state, procs, error, notes}
#   state: "queued" | "scanning" | "done" | "failed" | "stopped"
_jobs = {}
_lock = threading.Lock()

# Workers must not log through `host`: the SDK's host bridge writes a frame to
# stdout and then reads stdin, and that is the JSON-RPC pipe. A second thread
# using it interleaves a write into the protocol and steals a line of the
# response. So workers put their lines here and the dispatch thread drains them
# on the next poll, where logging is safe.
_logq = queue.Queue()

# The running scan: the pool doing the work, and the flag that calls it off.
_run = {"pool": None, "stop": None, "started": 0.0}

# One host at a time per thread, and few enough threads not to be rate-limited
# off the Falcon API — the aim is that a small fleet finishes quickly, not that a
# large one arrives all at once.
MAX_WORKERS = 8

# A scan of a large fleet returns a lot of rows, and every one of them crosses
# the RTR response, this process, and the UI — so there is a cap per host.
#
# Set far higher than the device list's, because the shape of the data is
# different: a host has a handful of physical interfaces and can have hundreds of
# virtual ones — container veths, tunnels, VPN adapters — and on a container host
# that is the whole list. Generous enough that the cap is a guard rather than a
# limit, and when it does bite the host says so on its own row.
MAX_ROWS_PER_HOST = 5000

# How long the script itself may run on the endpoint. Falcon caps this at 600.
RTR_TIMEOUT = 600

# The most one `runscript -Raw` may carry. The command travels as a single string
# in a REST body, and the figures quoted for RTR sit around 4 KB — so this is set
# below that and enforced when the script is built, where it is a loud failure in
# a test, rather than discovered on a host as empty output.
MAX_SCRIPT_BYTES = 4000

# How long a poll waits before answering. The host re-invokes an `auto` action as
# soon as the view renders, so without this the progress loop would spin as fast
# as the two processes can exchange frames, for as long as the scan lasts.
POLL_SECONDS = 0.6


class _Stopped(Exception):
    """Raised inside a worker when Stop was pressed — a cancellation, not a
    failure, and shown as one."""


class _UnknownOS(Exception):
    """The host's OS is not one this module can read, so nothing is run on it."""

    def __init__(self, platform):
        super().__init__(f"unsupported OS: {platform}")
        self.platform = platform


# --------------------------------------------------------------------------- #
# Falcon RTR (auth and the inventory come from the crowdstrike capability).
# --------------------------------------------------------------------------- #
def _http(method, url, token, body=None):
    headers = {"Authorization": f"Bearer {token}"}
    data = None
    if body is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(body).encode()
    req = urllib.request.Request(url, method=method, headers=headers, data=data)
    # Walking three registry views (or four package databases) takes longer
    # than a notification does, so the read timeout is generous.
    with urllib.request.urlopen(req, timeout=120) as resp:
        raw = resp.read().decode("utf-8")
        return resp.status, (json.loads(raw) if raw else {})


def _auth(host):
    """Bearer token + API base from the crowdstrike capability."""
    token = (host.call("crowdstrike", "token", {}) or {}).get("token")
    base = (
        (host.call("crowdstrike", "api", {}) or {})
        .get("base_url", "https://api.crowdstrike.com")
        .rstrip("/")
    )
    if not token:
        raise RuntimeError(
            "no CrowdStrike token — configure the crowdstrike module first"
        )
    return token, base


def _rtr_one(hid, platform, token, base, stop):
    """Enumerate ONE host and return its stdout.

    One RTR session per host rather than one batch across many: a batch returns
    when its slowest member does, and this module's whole point is that a finished
    host is usable while the others are still going. The cost is an init call per
    host, which is what the thread pool is for.

    Raises on failure — the caller turns that into the host's error state. Never
    touches `host`: this runs on a worker thread, and the SDK's host bridge is the
    JSON-RPC pipe on stdio, which only the dispatch thread may write to.
    """
    if stop.is_set():
        raise _Stopped()
    # Chosen first, so a host whose OS we cannot read costs no RTR session and
    # nothing is run on it.
    passes = _script_for(platform)
    st, init = _http(
        "POST",
        f"{base}/real-time-response/combined/batch-init-session/v1",
        token,
        {"host_ids": [hid], "timeout": 120},
    )
    batch_id = init.get("batch_id")
    if not batch_id:
        raise RuntimeError(f"no RTR session (RTR enabled for this host?) HTTP {st}")
    resources = init.get("resources") or {}
    if isinstance(resources, dict):
        for r in resources.values():
            for e in r.get("errors") or []:
                raise RuntimeError(str(e.get("message", e)))

    # One session, then each pass over it. Their outputs are concatenated: the
    # parser only ever sees lines, so it neither knows nor needs to know that they
    # arrived in several pieces.
    collected, troubles = [], []
    for label, script in passes:
        if stop.is_set():
            raise _Stopped()
        # `-Timeout` before `-Raw`: the raw block ends at a fence, and anything
        # after that fence is ambiguous, so no argument goes there.
        command_string = f"runscript -Timeout={RTR_TIMEOUT} -Raw=```" + script + "```"
        st, res = _http(
            "POST",
            f"{base}/real-time-response/combined/batch-admin-command/v1",
            token,
            {
                "batch_id": batch_id,
                "base_command": "runscript",
                "command_string": command_string,
            },
        )
        per_host = (res.get("combined", {}).get("resources", {}) or {}).get(hid)
        if per_host is None:
            troubles.append(f"{label}: no answer (HTTP {st})")
            continue
        stdout = per_host.get("stdout") or ""
        if "#begin" in stdout:
            collected.append(stdout)
            continue
        # The script prints `#begin` before doing anything, so its absence does
        # not mean "nothing here" — it means the pass did not run. One pass
        # failing is not the host failing, so it is recorded and the rest go on.
        stderr = (per_host.get("stderr") or "").strip()
        errs = "; ".join(str(e.get("message", e)) for e in per_host.get("errors") or [])
        troubles.append(f"{label}: {errs or stderr or 'did not run'}")

    if not collected:
        # Every pass failed, so there is nothing to show and a reason to give.
        raise RuntimeError("; ".join(troubles) or "the script did not run on this host")
    if troubles:
        # Some of the picture is missing, and the operator has to know which part
        # rather than be handed a short list that looks complete.
        collected.append("#err=" + "; ".join(troubles) + "\n")
    return "\n".join(collected)


# --------------------------------------------------------------------------- #
# The enumeration scripts.
#
# Each prints one entry per line as
#     name|pid|ppid|parent|user|started|path|command
# plus `#`-prefixed metadata lines. A flat line format rather than JSON on
# purpose: RTR hands back stdout as loose text and truncates it, and a truncated
# JSON document is worth nothing while a truncated list of lines is worth all but
# the last line.
#
# **No backticks.** The script is sent inside an RTR ```...``` block, and a
# backtick is also PowerShell's escape character — one in here corrupts the
# command on the wire, so the Windows script escapes nothing and quotes with
# single quotes throughout.
# --------------------------------------------------------------------------- #

# Windows. `Get-CimInstance Win32_Process` carries the command line and the
# parent, which `Get-Process` does not — and the command line is most of the
# value here: a process named `powershell.exe` says nothing, its arguments say
# everything.
#
# The owner comes from a separate call per process, which on a busy host is
# hundreds of calls. It is asked for only while there is budget, because a slow
# scan that times out returns nothing at all, and a list without owners beats no
# list.
_WIN = r"""
Write-Output '#begin'
$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'
$VerbosePreference = 'SilentlyContinue'
$DebugPreference = 'SilentlyContinue'
$InformationPreference = 'SilentlyContinue'
$n = 0
function Clean($s) {
  if ($null -eq $s) { return '' }
  return (([string]$s) -replace '[\r\n\|]', ' ').Trim()
}
function Emit($line) {
  if ($script:n -ge __LIMIT__) { Write-Output '#truncated'; exit }
  $script:n = $script:n + 1
  Write-Output $line
}
try {
$procs = @(Get-CimInstance Win32_Process)
# Owners are one call each. Past this many processes the machine is busy enough
# that the calls would cost more than the answer is worth.
$owners = $procs.Count -le 400
$names = @{}
foreach ($p in $procs) { $names[[string]$p.ProcessId] = (Clean $p.Name) }
foreach ($p in $procs) {
  $who = ''
  if ($owners) {
    $o = Invoke-CimMethod -InputObject $p -MethodName GetOwner
    if ($o -and $o.User) {
      $who = (Clean $o.Domain) + '\' + (Clean $o.User)
      $who = $who.TrimStart('\')
    }
  }
  $started = ''
  if ($p.CreationDate) { $started = $p.CreationDate.ToString('yyyy-MM-dd HH:mm:ss') }
  $ppid = [string]$p.ParentProcessId
  Emit (@((Clean $p.Name), [string]$p.ProcessId, $ppid, (Clean $names[$ppid]), $who,
          $started, (Clean $p.ExecutablePath), (Clean $p.CommandLine)) -join '|')
}
if (-not $owners) { Write-Output '#no-owners' }
} catch { Write-Output ('#err=' + ($_.Exception.Message -replace '[\r\n\|]', ' ')) }
"""

# Linux. `ps` with an explicit format rather than the default columns, so the
# output does not depend on which `ps` the distribution ships.
#
# `args` must be last: it is the one field that contains spaces, so everything
# else is read by position and the remainder of the line is the command.
_LINUX = r"""
exec 2>/dev/null
echo '#begin'
LIMIT=__LIMIT__
# `user:32=` rather than `user=`: the default column truncates a long name to
# eight characters and marks it with a `+`, which is not a username and cannot be
# searched for as one.
ps -eo pid=,ppid=,user:32=,lstart=,comm=,args= 2>/dev/null |
  awk -v lim="$LIMIT" '
    {
      pid = $1; ppid = $2; user = $3
      # lstart is five fields ("Mon Jan  1 00:00:00 2025"), fixed width in
      # fields even when the day is single-digit.
      started = $5 " " $6 " " $7 " " $8
      comm = $9
      args = ""
      for (i = 10; i <= NF; i++) args = args $i " "
      gsub(/\|/, " ", user); gsub(/\|/, " ", comm); gsub(/\|/, " ", args)
      if (++c > lim) { print "#truncated"; exit }
      # The executable path is not in ps output; the first word of args is the
      # closest thing, and is left to the parser to take.
      print comm "|" pid "|" ppid "||" user "|" started "||" args
    }'
# Parent names need the whole table first, so they are filled in on our side
# rather than by a second ps per process.
"""

# macOS. The same `ps`, which is BSD rather than GNU here — the format keywords
# used above are the ones both accept.
_MAC = r"""
exec 2>/dev/null
echo '#begin'
LIMIT=__LIMIT__
ps -Ao pid=,ppid=,user=,lstart=,comm=,args= 2>/dev/null |
  awk -v lim="$LIMIT" '
    {
      pid = $1; ppid = $2; user = $3
      started = $5 " " $6 " " $7 " " $8
      comm = $9
      args = ""
      for (i = 10; i <= NF; i++) args = args $i " "
      gsub(/\|/, " ", user); gsub(/\|/, " ", comm); gsub(/\|/, " ", args)
      if (++c > lim) { print "#truncated"; exit }
      print comm "|" pid "|" ppid "||" user "|" started "||" args
    }'
"""


# Falcon's `platform_name`, lowercased, to the script that can read that OS.
# Matched on a prefix because the field is not a closed set: "Windows", "Linux",
# "Mac" and "macOS" have all been seen in the wild.
_SCRIPTS = (("win", "win"), ("mac", "mac"), ("linux", "linux"), ("ubuntu", "linux"),
            ("rhel", "linux"), ("centos", "linux"), ("debian", "linux"),
            ("amazon", "linux"), ("suse", "linux"), ("oracle", "linux"))

# The scripts to run on each OS, in order, as (label, body).
#
# Windows is **three** scripts rather than one, and not for tidiness: a
# `runscript -Raw` command travels as one string in a REST body, and that string
# is not unbounded. The single script came to 4.8 KB, which is close enough to the
# limits quoted for RTR that a host would refuse it — and a refused script comes
# back as empty output, which is indistinguishable from a machine with nothing to
# report. Splitting also buys failure granularity: if reading the scheduled tasks
# trips over one bad task, the Run keys have already been returned.
_PASSES = {
    "win": (("all", "_WIN"),),
    "linux": (("all", "_LINUX"),),
    "mac": (("all", "_MAC"),),
}


def _minify(script):
    """Drop comment-only and blank lines.

    The comments in these scripts are worth a great deal in this file and nothing
    at all on the wire, where they are the difference between a command that fits
    and one that may not: the autorun script carries far more explanation than the
    others, and an RTR command string is not unbounded. Only lines whose first
    non-space character is `#` go — so `echo '#begin'`, which starts with `echo`,
    is untouched, and no string literal is ever cut into.
    """
    kept = [ln for ln in script.split("\n")
            if ln.strip() and not ln.lstrip().startswith("#")]
    return "\n".join(kept) + "\n"


def _script_for(platform, limit=MAX_ROWS_PER_HOST):
    """The enumeration scripts for a Falcon `platform_name`, as (label, script).

    Raises [`_UnknownOS`] rather than guessing. Guessing would mean falling
    through to the shell script, and on a Windows host that does not fail
    cleanly — it comes back empty, and that host then reads as a machine with
    **no software installed**. Which is the one wrong conclusion this module must
    never invite, so an OS we cannot name is a visible failure instead. Falcon
    also reports iOS, Android and Kubernetes nodes; none can be enumerated this
    way.
    """
    p = (platform or "").strip().lower()
    which = next((kind for prefix, kind in _SCRIPTS if p.startswith(prefix)), None)
    if which is None:
        raise _UnknownOS(platform or "(not reported)")
    bodies = globals()
    out = []
    for label, name in _PASSES[which]:
        body = bodies[name]
    # This file is checked out with CRLF, so the literals above carry \r on
    # every line. PowerShell copes; /bin/sh does not — `LIMIT=400\r` compares
    # against a value with a carriage return in it and every `done` becomes an
    # unknown command. So the script is normalised to LF whichever platform it is
    # for, rather than leaving it to how this file happens to be checked out.
        script = _minify(body.replace("__LIMIT__", str(int(limit)))).replace("\r\n", "\n")
        # The script is sent inside an RTR ```…``` block, so a backtick anywhere
        # in it — including in a comment written out of Markdown habit — closes
        # that block early and corrupts the command on the wire. It fails as a
        # script that does not run rather than as an error anybody sees, so it is
        # caught here instead.
        if "`" in script:
            bad = next(n for n, ln in enumerate(script.splitlines(), 1) if "`" in ln)
            raise AssertionError(f"backtick in {label} for {platform}, line {bad}")
        if len(script) > MAX_SCRIPT_BYTES:
            raise AssertionError(
                f"{label} for {platform} is {len(script)}B, over the "
                f"{MAX_SCRIPT_BYTES}B a single runscript may carry — split it")
        out.append((label, script))
    return out


def _parse(stdout, hostname, host_id):
    """One host's stdout into process rows, plus what the metadata lines said.

    The parent's *name* is filled in here rather than on the endpoint: the
    endpoint would need the whole table before it could answer, which on Windows
    means a second pass and on Unix a `ps` per process. Here it is one pass over
    a list already in hand.

    That name is the point of the column. `ppid 4812` tells you nothing;
    `4812 explorer.exe` tells you a user double-clicked something, and
    `4812 winword.exe` tells you a document did.
    """
    rows, by_pid, flags = [], {}, {"truncated": False, "error": "", "no_owners": False}
    for line in (stdout or "").splitlines():
        line = line.rstrip()
        if not line.strip():
            continue
        if line.startswith("#"):
            if line == "#begin":
                pass  # only proves the script ran; `_rtr_one` already checked
            elif line == "#truncated":
                flags["truncated"] = True
            elif line == "#no-owners":
                flags["no_owners"] = True
            elif line.startswith("#err="):
                # The endpoint stayed silent and told us instead.
                flags["error"] = line[5:].strip()
            continue
        # The command line is last and is the one field that may contain a pipe
        # of its own, so the split is bounded and the remainder kept whole.
        parts = line.split("|", 7)
        if len(parts) < 8:
            continue
        name, pid, ppid, parent, user, started, path, cmd = (p.strip() for p in parts)
        if not pid:
            continue
        # `ps` gives no executable path; the first word of the command line is
        # the closest thing to one, and is only used when the path is absent.
        if not path and cmd.startswith("/"):
            path = cmd.split()[0]
        row = {
            "host": hostname,
            "host_id": host_id,
            "name": name or (path.rsplit("/", 1)[-1] if path else ""),
            "pid": pid,
            "ppid": ppid,
            "parent": parent,
            "user": user,
            "started": started,
            "path": path,
            "cmd": cmd,
        }
        rows.append(row)
        by_pid[pid] = row["name"]
    # Fill in parent names from the table itself.
    for r in rows:
        if not r["parent"]:
            r["parent"] = by_pid.get(r["ppid"], "")
    rows.sort(key=lambda r: (r["name"].lower(), _int(r["pid"])))
    return rows, flags


def _int(v):
    """A pid as a number for sorting, and 0 for anything that is not one."""
    try:
        return int(v)
    except (TypeError, ValueError):
        return 0


# --------------------------------------------------------------------------- #
# Scanning: one worker per host, so a finished host is usable immediately.
# --------------------------------------------------------------------------- #
def _log(line):
    """Queue a line for the dispatch thread to log. Safe from any thread."""
    _logq.put(line)


def _set(hid, **fields):
    """Update one host's job state under the lock."""
    with _lock:
        job = _jobs.get(hid)
        if job is not None:
            job.update(fields)


def _worker(hid, token, base, stop):
    """Enumerate one host. Runs on a pool thread; touches only `_jobs` (locked),
    `_logq`, and the network."""
    with _lock:
        job = _jobs.get(hid)
        if job is None:
            return
        hostname, platform = job["hostname"], job["platform"]
    if stop.is_set():
        _set(hid, state="stopped")
        return
    _set(hid, state="scanning")
    try:
        stdout = _rtr_one(hid, platform, token, base, stop)
        rows, flags = _parse(stdout, hostname, hid)
        notes = []
        if flags["truncated"]:
            notes.append(t("note.truncated", n=MAX_ROWS_PER_HOST))
        if flags["no_owners"]:
            # Said plainly, because a blank Owner column otherwise reads as
            # "nobody" when it means "not asked": looking an owner up is a call
            # per process, and on a busy host those cost more than the column is
            # worth — a list without owners beats a scan that times out.
            notes.append(t("note.no_owners"))
        if flags["error"]:
            # The script caught something on the endpoint and reported it here
            # instead of showing it there. Surfaced as a note, not a failure: the
            # rows it did manage to send are still good.
            notes.append(flags["error"])
        if not rows and not notes:
            notes.append(t("note.empty"))
        _set(hid, state="done", procs=rows, notes=notes)
        _log(f"cs-processes: {hostname} — {len(rows)} process(es)")
    except _Stopped:
        _set(hid, state="stopped")
    except _UnknownOS as exc:
        _set(hid, state="skipped", error=str(exc))
        _log(f"cs-processes: {hostname} skipped — {exc}")
    except Exception as exc:  # noqa: BLE001
        _set(hid, state="failed", error=str(exc))
        _log(f"cs-processes: {hostname} failed — {exc}")


def _start(host, targets):
    """Queue `targets` and start the pool. Returns the status line.

    The token is fetched **here**, on the dispatch thread, and handed to the
    workers: asking for it from a worker would mean using the host bridge off the
    RPC thread.
    """
    if not targets:
        return t("status.none_selected")
    if _busy():
        return t("status.already_running")
    try:
        token, base = _auth(host)
    except Exception as exc:  # noqa: BLE001
        host.log(f"cs-processes: auth failed: {exc}")
        return str(exc)

    stop = threading.Event()
    with _lock:
        _jobs.clear()
        for target in targets:
            _jobs[target["id"]] = {
                "hostname": target.get("hostname") or target["id"],
                "platform": target.get("platform", ""),
                "state": "queued",
                "procs": [],
                "error": "",
                "notes": [],
            }
    pool = ThreadPoolExecutor(max_workers=min(MAX_WORKERS, len(targets)))
    _run.update(pool=pool, stop=stop, started=time.time())
    for target in targets:
        pool.submit(_worker, target["id"], token, base, stop)
    # Nothing is waited on: the pool is left running and the view polls it, so
    # the dispatch thread returns to drawing immediately.
    host.log(f"cs-processes: scanning {len(targets)} host(s) on "
             f"{min(MAX_WORKERS, len(targets))} thread(s)")
    return t("status.starting", n=len(targets))


def _busy():
    """Whether any host is still queued or in flight."""
    with _lock:
        return any(j["state"] in ("queued", "scanning") for j in _jobs.values())


def _drain_log(host):
    """Move whatever the workers queued into the host log. Dispatch thread only."""
    while True:
        try:
            host.log(_logq.get_nowait())
        except queue.Empty:
            return


def _tally():
    with _lock:
        states = [j["state"] for j in _jobs.values()]
        procs = sum(len(j["procs"]) for j in _jobs.values())
    return {
        "total": len(states),
        "done": states.count("done"),
        "failed": states.count("failed"),
        "stopped": states.count("stopped"),
        "skipped": states.count("skipped"),
        "running": states.count("scanning") + states.count("queued"),
        "procs": procs,
    }


def _targets_from(rows):
    return [
        {"id": h["id"], "hostname": h.get("hostname", ""),
         "platform": h.get("platform", "")}
        for h in rows
        if h.get("id")
    ]


# --------------------------------------------------------------------------- #
# Methods.
# --------------------------------------------------------------------------- #
@m.method("fetch")
def fetch(params, host):
    """Load the reachable inventory from the crowdstrike capability."""
    try:
        inv = host.call("crowdstrike", "hosts", {})
        # Only reachable hosts: RTR cannot open a session to a host that is
        # offline, so listing them as scannable would only produce failures.
        rows = inv.get("accessible", []) if isinstance(inv, dict) else []
        _hosts["rows"] = rows
        _status["msg"] = t("status.reachable", n=len(rows))
    except Exception as exc:  # noqa: BLE001
        _hosts["rows"] = None
        _status["msg"] = t("status.fetch_failed", err=exc)
        host.log(f"cs-processes: fetch failed: {exc}")
    return m._view_spec()


@m.method("scan_selected")
def scan_selected(params, host):
    """Start scanning the ticked hosts."""
    rows = _hosts["rows"] or []
    selected = [h for h in rows if params.get(f"sel_{h.get('id')}")]
    _status["msg"] = _start(host, _targets_from(selected))
    return m._view_spec()


@m.method("scan_all")
def scan_all(params, host):
    """Start scanning every host in the current list."""
    _status["msg"] = _start(host, _targets_from(_hosts["rows"] or []))
    return m._view_spec()


@m.method("progress")
def progress(params, host):
    """One tick of the progress loop: drain the workers' log lines, wait a beat,
    and re-render.

    The wait is the throttle. The host re-invokes an `auto` action the moment the
    view renders, so answering immediately would spin the loop as fast as the two
    processes can pass frames.
    """
    _drain_log(host)
    if _busy():
        time.sleep(POLL_SECONDS)
    t = _tally()
    if t["running"]:
        _status["msg"] = (
            f"scanning — {t['done']} of {t['total']} done, "
            f"{t['procs']} process(es) so far"
        )
    else:
        _shutdown_pool()
        parts = [f"{t['done']} host(s) scanned", f"{t['procs']} process(es)"]
        if t["failed"]:
            parts.append(f"{t['failed']} failed")
        if t["stopped"]:
            parts.append(f"{t['stopped']} stopped")
        if t["skipped"]:
            parts.append(f"{t['skipped']} unsupported")
        _status["msg"] = " · ".join(parts)
    return m._view_spec()


def _shutdown_pool():
    """Let the finished pool go. Not blocking: every worker has already left."""
    pool = _run.get("pool")
    if pool is not None:
        pool.shutdown(wait=False)
        _run["pool"] = None


@m.method("stop")
def stop(params, host):
    """Call off the scan.

    A host already in flight finishes its current HTTP call — there is no way to
    un-ask a request that is out — but nothing new is started, and anything still
    queued is marked stopped rather than left looking as though it is coming.
    """
    ev = _run.get("stop")
    if ev is not None:
        ev.set()
    with _lock:
        for job in _jobs.values():
            if job["state"] == "queued":
                job["state"] = "stopped"
    host.log("cs-processes: stop requested")
    _status["msg"] = t("status.stopping")
    return m._view_spec()


# --------------------------------------------------------------------------- #
# One host's processes, in its own tab.
# --------------------------------------------------------------------------- #
def columns():
    """Column headings, in the current language. A function rather than a
    constant, which would freeze whichever language the module was imported in."""
    return [t("col.process"), t("col.pid"), t("col.parent"),
            t("col.owner"), t("col.started"), t("col.cmd")]


def _cells(r):
    parent = r.get("parent", "")
    ppid = r.get("ppid", "")
    # The parent as "4812 explorer.exe" — the pid alone identifies nothing, the
    # name alone cannot be followed back up the tree.
    parent = f"{ppid} {parent}".strip() if (ppid or parent) else ""
    return [r.get("name", ""), r.get("pid", ""), parent, r.get("user", ""),
            r.get("started", ""), r.get("cmd", "")]


# Processes shown in a host tab, by row id, so `about` can resolve one. Keyed
# "<host id>:<index>" rather than by index alone: several host tabs are open at
# once, and row 3 means a different process in each.
_shown = {}

# The filter text per open host tab, so two tabs can be narrowed differently.
_query = {}


@m.method("open_host")
def open_host(params, host):
    """A finished host's processes, opened in a tab. The double-click target."""
    _sync_locale()
    hid = str(params.get("id", ""))
    with _lock:
        job = dict(_jobs.get(hid) or {})
    if not job:
        return Window(t("ui.col_host"), [Label(t("host.unknown"))]).to_spec()
    name = job["hostname"]
    if job["state"] != "done":
        return Window(name, [
            Label(name, style="heading"),
            Label(state_text(job["state"]), style="weak"),
            Label(job["error"], style="weak") if job["error"] else Separator(),
        ]).to_spec()

    # A filter typed in this tab arrives with the call; otherwise the one this tab
    # was last left with, so a refresh does not silently widen the list.
    if "query" in params:
        _query[hid] = params.get("query") or ""
    query = (_query.get(hid) or "").lower()

    procs = job["procs"]
    rows, ids = [], []
    for i, r in enumerate(procs):
        cells = _cells(r)
        # The image path is searched even though it has no column: looking for
        # everything running out of \\Temp\\ is the question, and the column that
        # would answer it is too wide to show.
        if query and query not in (" ".join(cells) + " " + r.get("path", "")).lower():
            continue
        rid = f"{hid}:{i}"
        _shown[rid] = r
        ids.append(rid)
        rows.append(cells)

    users = {}
    for r in procs:
        if r.get("user"):
            users[r["user"]] = users.get(r["user"], 0) + 1
    breakdown = ", ".join(f"{n} {u}" for u, n in
                          sorted(users.items(), key=lambda kv: -kv[1])[:4])

    widgets = [
        Label(name, style="heading"),
        Label(t("host.summary", n=len(procs)), style="weak"),
    ]
    if breakdown:
        widgets.append(Label(breakdown, style="weak"))
    for note in job["notes"]:
        widgets.append(Label("! " + note, style="weak"))
    tools = [
        Text("query", label=t("ui.search"), placeholder=t("ui.search_hint"),
             default=_query.get(hid, "")),
        # Re-opens this same tab with the filter applied; the host id rides along
        # so the button knows which host it is filtering.
        Button(t("ui.filter"), calls="open_host", args={"id": hid}),
    ]
    if _has_reports():
        # This host alone, as this tab shows it. Not `open_in_tab`: the report
        # provider answers with a pop-up, and one opened into a tab of its own
        # leaves that tab empty.
        tools.append(Button(t("report.make"), calls="make_report", args={"id": hid}))
    widgets.append(Row(tools))
    widgets.append(Separator())
    if rows:
        if query:
            widgets.append(Label(t("ui.shown_of", shown=len(rows), total=len(procs)),
                                 style="weak"))
        widgets.append(Table(
            columns(), rows, row_ids=ids,
            menu=[MenuItem(t("proc.about"), capability=CAP, method="about",
                           open_in_tab=True)],
            on_activate=(CAP, "about")))
    else:
        widgets.append(Label(
            t("ui.no_match") if query else t("host.nothing"), style="weak"))
    return Window(name, widgets).to_spec()


@m.method("about")
def about(params, host):
    """One process, opened in a tab."""
    _sync_locale()
    r = _shown.get(str(params.get("id", "")))
    if not r:
        return Window(t("proc.window"), [Label(t("proc.gone"))]).to_spec()

    def field(label, value):
        return Label(f"{label}: {value}" if value else f"{label}: —")

    parent = r.get("parent", "")
    ppid = r.get("ppid", "")
    return Window(r.get("name") or t("proc.window"), [
        Label(r.get("name") or t("proc.unnamed"), style="heading"),
        Label(t("proc.pid", n=r.get("pid", "?")), style="weak"),
        Separator(),
        field(t("proc.host"), r.get("host")),
        field(t("proc.owner"), r.get("user")),
        field(t("proc.parent"), f"{ppid} {parent}".strip()),
        field(t("proc.started"), r.get("started")),
        field(t("proc.image"), r.get("path")),
        Separator(),
        # On its own line and last: it is the longest thing here and the thing
        # most often copied out of this screen.
        Label(t("proc.cmd"), style="strong"),
        Label(r.get("cmd") or "—"),
        Separator(),
        field(t("proc.falcon_id"), r.get("host_id")),
    ]).to_spec()


# --------------------------------------------------------------------------- #
# The report, when a provider is installed.
# --------------------------------------------------------------------------- #
def _has_reports():
    """Whether a report provider is installed right now.

    Asked each draw rather than cached: `report.build` is optional, and a module
    installed while this tab is open should make the button appear.
    """
    try:
        return m.host.has_capability("report.build")
    except Exception:  # noqa: BLE001
        return False


def _counted(rows, key, most=None):
    """How many rows each value of `key` accounts for, most first — a chart.
    `most` keeps the head of it, where the tail would be a bar per row."""
    counts = {}
    for r in rows:
        name = r.get(key) or "—"
        counts[name] = counts.get(name, 0) + 1
    data = [{"label": k, "value": v}
            for k, v in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))]
    return data[:most] if most else data


def _host_report(hid, job):
    """One host as a report: what its tab shows, filter included — a report that
    quietly widened back out to every process would not be the thing the person
    asked for, and they would have no way to tell."""
    name = job["hostname"]
    query = (_query.get(hid) or "").lower()
    # The image path is searched even though it has no column, as in the tab.
    procs = [r for r in job["procs"]
             if not query or query in (" ".join(_cells(r)) + " " + r.get("path", "")).lower()]
    owners = len({r["user"] for r in procs if r.get("user")})
    # The ten owners with the most, not a bar for every service account.
    chart = _counted([r for r in procs if r.get("user")], "user", most=10)
    return {
        "title": t("report.title_host"),
        "subtitle": t("report.subtitle_host", host=name, n=len(procs)),
        # Filed under the machine it is about. The report module adds the date; a
        # folder of files all called "processes" is one nobody can find anything in.
        "file_name": f"{name}_processes",
        "summary": [t("report.line_items", n=len(procs)),
                    t("report.line_a", n=owners)] + list(job["notes"]),
        "charts": [{"title": t("report.by_owner"), "data": chart}] if chart else [],
        "sections": [{"heading": t("report.items", n=len(procs)),
                      "columns": columns(), "rows": [_cells(r) for r in procs]}] if procs else [],
    }


def _fleet_report(jobs):
    """The fleet as a report: a line per host that was read — how much is on it,
    as the fleet screen lists it — and the hosts that were not. A host's every
    process is its own report, from its tab: here it would be hundreds of pages
    nobody asked for."""
    done = sorted((j for j in jobs.values() if j["state"] == "done"),
                  key=lambda j: j["hostname"].lower())
    # Listed rather than counted: an absent host is the one case where an empty
    # result means nothing at all.
    bad = sorted([j["hostname"], j["error"]] for j in jobs.values()
                 if j["state"] in ("failed", "skipped"))
    rows, everything, notes = [], [], []
    for j in done:
        users = len({r["user"] for r in j["procs"] if r.get("user")})
        named = sum(1 for r in j["procs"] if r.get("cmd"))
        rows.append([j["hostname"], str(len(j["procs"])), str(users), str(named)])
        everything += j["procs"]
        notes += [f"{j['hostname']}: {note}" for note in j["notes"]]
    # By host, not by owner: SYSTEM owns most of every machine, and a bar saying
    # so says nothing about the fleet. The busiest ten, not a bar per host.
    chart = sorted(({"label": j["hostname"], "value": len(j["procs"])} for j in done),
                   key=lambda d: (-d["value"], d["label"].lower()))[:10]
    sections = []
    if rows:
        sections.append({"heading": t("report.hosts", n=len(rows)),
                         "columns": [t("ui.col_host"), t("ui2.col_procs"), t("ui2.col_owners"),
                                     t("ui2.col_withcmd")],
                         "rows": rows})
    if bad:
        sections.append({"heading": t("ui.not_scanned", n=len(bad)),
                         "columns": [t("ui.col_host"), t("ui.col_why")], "rows": bad})
    summary = [t("report.line_hosts", n=len(done)),
               t("report.line_items", n=len(everything))]
    if bad:
        summary.append(t("report.line_not_read", n=len(bad)))
    return {
        "title": t("report.title"),
        "subtitle": t("report.subtitle_fleet", hosts=len(done), n=len(everything)),
        "file_name": "fleet_processes",
        "summary": summary + notes,
        "charts": [{"title": t("report.by_host"), "data": chart}] if chart else [],
        "sections": sections,
    }


def report_spec(hid=None):
    """The last scan as a report spec — with `hid`, one host of it — or `None`
    when there is nothing to report."""
    with _lock:
        jobs = {k: dict(j) for k, j in _jobs.items()}
    if hid is not None:
        job = jobs.get(hid)
        if not job or job["state"] != "done":
            return None
        spec = _host_report(hid, job)
    else:
        if not any(j["state"] in ("done", "failed", "skipped") for j in jobs.values()):
            return None
        spec = _fleet_report(jobs)
    # Always the provider's preview. What the document is — a PDF — the ground
    # it is printed on, and whether it is signed are decided there, beside the
    # thing being saved, by the module that owns the question.
    spec["format"] = "view"
    return spec


@m.method("make_report")
def make_report(params, host):
    """Hand the last scan — or, with ``{"id"}``, one host of it — to whatever
    report provider is installed."""
    _sync_locale()
    spec = report_spec(str(params.get("id") or "") or None)
    if spec is None:
        return Window(t("report.title"), [
            Label(t("report.nothing"), style="strong"),
        ]).to_spec()
    try:
        built = host.call("report.build", "build", spec)
    except Exception as exc:  # noqa: BLE001
        return Window(t("report.title"), [
            Label(t("report.failed"), style="strong"),
            Label(str(exc), style="weak"),
        ]).to_spec()
    # The provider answers with a screen of its own — it is the report.
    if isinstance(built, dict) and built.get("widgets") is not None:
        return built
    # A provider that writes a file and acknowledges with nothing. The one
    # shipped with Limen always answers with a screen; this is for any other.
    return Window(t("report.title"), [
        Label(t("report.written"), style="strong"),
    ]).to_spec()


@m.method("processes")
def processes(params, host):
    """The capability method: every scanned process as data, for other modules.

    Reports the last scan rather than starting one — a scan runs across the fleet
    and takes minutes, which is not something another module should set off by
    asking a question.

    ``{"name": "powershell"}`` matches the process name and ``{"cmd": "-enc"}``
    anywhere in the command line or image path, both case-insensitively. The
    second is the one worth having: it is how a single indicator is checked
    against the whole fleet at once.
    """
    with _lock:
        if not _jobs:
            return {"error": "nothing scanned yet", "total": 0, "processes": []}
        rows = [r for j in _jobs.values() for r in j["procs"]]
        failed = {j["hostname"]: j["error"] for j in _jobs.values()
                  if j["state"] in ("failed", "skipped")}
        # Computed here rather than by calling `_busy()`: that takes `_lock` too,
        # and `_lock` is a plain Lock, not an RLock.
        pending = any(j["state"] in ("queued", "scanning") for j in _jobs.values())
    name = (params.get("name") or "").strip().lower()
    if name:
        rows = [r for r in rows if name in r["name"].lower()]
    cmd = (params.get("cmd") or "").strip().lower()
    if cmd:
        rows = [r for r in rows
                if cmd in r["cmd"].lower() or cmd in r["path"].lower()]
    user = (params.get("user") or "").strip().lower()
    if user:
        rows = [r for r in rows if user in r["user"].lower()]
    return {
        "note": "Processes running across CrowdStrike fleet hosts, read over RTR. "
                "`cmd` is the full command line, which is where the answer usually "
                "is. `parent` is the parent's name, resolved from the same table. "
                "An empty `user` on Windows can mean the host had too many "
                "processes to look owners up, not that it has none — the host's "
                "note says which.",
        "scanning": pending,
        "total": len(rows),
        "hosts": len({r["host_id"] for r in rows}),
        "failed_hosts": failed,
        "processes": rows,
    }

# --------------------------------------------------------------------------- #
# The screen.
# --------------------------------------------------------------------------- #
# What each job state says, and which `Step` icon it gets. "pending" is the idle
# dot, "loading" the spinner, "done" the check — so a failed or stopped host
# reads as finished-and-not-ok rather than as still going, which is the one thing
# it must never look like.
def state_text(state):
    """What a host's row says it is doing, in the current language."""
    return t("state." + state) if state in (
        "queued", "scanning", "done", "failed", "stopped", "skipped") else state
_STATE_ICON = {
    "queued": "pending",
    "scanning": "loading",
    "done": "done",
    "failed": "pending",
    "stopped": "pending",
    "skipped": "pending",
}


class Step:
    """A progress step: an animated spinner that morphs into a check.

    Built as a raw spec rather than imported, because the Python SDK has no `Step`
    even though the host renders one. Same for the view's `auto` below.
    """

    def __init__(self, label="", state="pending"):
        self.label, self.state = label, state

    def to_spec(self):
        return {"kind": "step", "label": self.label, "state": self.state}


def _host_lines(widgets, rows):
    """One line per host: the tick box that selects it, and — once a scan has
    touched it — the live state beside it."""
    with _lock:
        jobs = {hid: dict(j) for hid, j in _jobs.items()}
    for h in rows:
        hid = h.get("id", "")
        job = jobs.get(hid)
        line = [Checkbox(f"sel_{hid}", label=h.get("hostname", "?"))]
        if job:
            text = state_text(job["state"])
            if job["state"] == "done":
                text = t("status.items", n=len(job["procs"]))
            elif job["state"] == "failed" and job["error"]:
                text = t("state.failed_why", why=job["error"][:60])
            line.append(Step(label=text, state=_STATE_ICON.get(job["state"], "pending")))
        widgets.append(Row(line))
        detail = "   ·   ".join(p for p in [
            h.get("os", ""),
            f"SN {h['serial']}" if h.get("serial") else "",
            h.get("tags", ""),
        ] if p)
        if detail:
            widgets.append(Label("      " + detail, style="weak"))


def _finished_table(widgets):
    """The hosts that have finished, double-click to open one.

    Separate from the lines above because a table row is what carries a
    double-click, and because it is the natural place to be told which hosts are
    ready to look at while the rest are still running.
    """
    with _lock:
        done = [(hid, dict(j)) for hid, j in _jobs.items() if j["state"] == "done"]
    if not done:
        return
    done.sort(key=lambda kv: kv[1]["hostname"].lower())
    rows, ids = [], []
    for hid, j in done:
        users = len({r["user"] for r in j["procs"] if r.get("user")})
        named = sum(1 for r in j["procs"] if r.get("cmd"))
        rows.append([j["hostname"], str(len(j["procs"])), str(users), str(named)])
        ids.append(hid)
    widgets += [
        Separator(),
        Label(t("ui.scanned", n=len(rows)), style="strong"),
        Table([t("ui.col_host"), t("ui2.col_procs"), t("ui2.col_owners"),
               t("ui2.col_withcmd")], rows,
              row_ids=ids, on_activate=(CAP, "open_host"),
              menu=[MenuItem(t("ui.open_host"), capability=CAP, method="open_host",
                             open_in_tab=True)]),
    ]


def _failed_table(widgets):
    """Hosts that were not read, listed rather than counted.

    An absent host is the one case where an empty result means nothing at all, so
    the operator has to know which machine to go and look at by hand. Hosts whose
    OS this module cannot read are in here too: they are not failures, but they
    are equally not answers, and leaving them out would quietly shrink the fleet.
    """
    with _lock:
        bad = [dict(j) for j in _jobs.values() if j["state"] in ("failed", "skipped")]
    if not bad:
        return
    widgets += [
        Separator(),
        Label(t("ui.not_scanned", n=len(bad)), style="strong"),
        Table([t("ui.col_host"), t("ui.col_why")], sorted([[j["hostname"], j["error"]] for j in bad])),
    ]


@m.ui
def ui():
    _sync_locale()
    widgets = [
        Label(t("ui.title"), style="heading"),
        Label(t("ui.subtitle"), style="weak"),
    ]

    rows = _hosts["rows"]
    running = _busy()
    toolbar = [Button(t("ui.fetch_hosts"), calls="fetch", primary=rows is None,
                      enabled=not running)]
    if rows:
        toolbar.append(Button(t("ui.scan_selected"), calls="scan_selected",
                              primary=True, enabled=not running))
        toolbar.append(Button(t("ui.scan_all"), calls="scan_all",
                              enabled=not running))
        # Only offered while there is something to stop, so it is never a button
        # that does nothing.
        if running:
            toolbar.append(Button(t("ui.stop"), calls="stop", danger=True))
    # Offered once a scan has something to say, and not while one is running:
    # a report of half a fleet reads like a report of the fleet.
    with _lock:
        scanned = any(j["state"] in ("done", "failed", "skipped") for j in _jobs.values())
    if scanned and _has_reports():
        toolbar.append(Button(t("report.make"), calls="make_report", enabled=not running))
    widgets.append(Row(toolbar))

    if _status["msg"]:
        widgets.append(Label(_status["msg"], style="weak"))

    if rows is not None:
        widgets.append(Separator())
        widgets.append(Label(t("ui.reachable", n=len(rows)), style="strong"))
        if not rows:
            widgets.append(Label(t("ui.no_reachable"), style="weak"))
        _host_lines(widgets, rows)

    _finished_table(widgets)
    _failed_table(widgets)

    spec = Window(t("ui.title"), widgets).to_spec()
    # While anything is still running, ask the host to call `progress` as soon as
    # this has drawn — that loop is what makes the spinners move and the finished
    # hosts appear one at a time. It stops being emitted the moment the work is
    # done, which is what ends the loop.
    if running:
        spec["auto"] = {"capability": CAP, "method": "progress", "args": {}}
    return spec


if __name__ == "__main__":
    m.run()
