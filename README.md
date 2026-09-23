# limen-crowdstrike-processes

What is running on every CrowdStrike fleet host, read over Real Time Response —
name, pid, parent, owner, start time, image path, and the **full command line**.

## Why the command line

A process called `powershell.exe` says nothing. Its arguments say everything:
whether it is a scheduled maintenance script or a base64 blob piped in from the
internet.

Falcon's own process telemetry is event-shaped — it tells you what *started*.
This is the table as it stands **right now**, which is the question actually asked
during triage.

## How it works

One RTR session **per host**, on a small thread pool. Tick the hosts, press Scan,
and the list fills in as answers arrive — a spinner beside each host while it
runs, and a double-click on any finished host opens its processes in a tab
**while the rest are still scanning**. Stop calls off whatever has not started.

| Platform | Source |
|---|---|
| Windows | `Win32_Process` — carries the command line and the parent that `Get-Process` does not |
| Linux / macOS | `ps` with an explicit output format, so the result does not depend on which `ps` ships |

**The parent's name is resolved here**, not on the endpoint — which would need
the whole table before it could answer, meaning a second pass on Windows and a
`ps` per process on Unix. `ppid 4812` tells you nothing; `4812 explorer.exe` tells
you somebody double-clicked, and `4812 winword.exe` tells you a document did.

**Owners on Windows cost a call each.** On a host with hundreds of processes those
calls would cost more than the column is worth, and a scan that times out returns
nothing at all — so past a threshold they are skipped and the host's row says so.
A blank Owner column means *not asked*, never *nobody*, and the note is there so
the two are not confused.

The command line is split off last and kept whole, so a command that contains a
pipe of its own survives intact.

## Nothing shows on the endpoint

Every PowerShell output stream is set to `SilentlyContinue`, the body is wrapped
so an unforeseen throw cannot surface, and on Unix `stderr` is closed for the
whole script. No files are written and no window is opened.

Read-only: the process table is read. Nothing is started, stopped or signalled.
But read-only is a property of the script, not of the permission, so the
permission stays the honest one — `run_hosts`. **This executes code on your
fleet.**

## It needs no privileges on your own machine

`network` and `run_hosts`, and nothing else. No `admin`, no `elevate`, no
`may_require_admin`. The privilege it needs is remote and Falcon-side — the RTR
admin tier for `runscript` — a scope on your API client.

## Requires

* The [`crowdstrike`](https://github.com/CRC-BARRACUDA/limen-crowdstrike) module,
  configured. It owns the credentials; this module owns none.
* RTR enabled, with the admin tier on the API client.

## Capability

Provides `crowdstrike.processes`.

```
processes                       -> the last scan as data
processes {"name": "powershell"} -> by process name
processes {"cmd": "-enc"}        -> anywhere in the command line or image path
processes {"user": "SYSTEM"}     -> by owner
```

The `cmd` lookup is the one worth having: it is how a single indicator is checked
against the whole fleet at once.

## Licence

GPL-3.0-or-later.
