# ptrace

`ptrace_scope` is a Yama setting (`/proc/sys/kernel/yama/ptrace_scope`) that limits who may use `ptrace(PTRACE_ATTACH)` on a process. It sits on top of the kernel's normal rules (same UID, target dumpable, and so on) and can only make them stricter.

| Value | Name | Who may attach to a process |
|---|---|---|
| 0 | classic | Any process of the same user. This is the traditional Unix behavior. |
| 1 | restricted | Only its ancestors (parent, grandparent, and so on), or a process with `CAP_SYS_PTRACE`. The target can also nominate a tracer with `prctl(PR_SET_PTRACER, pid)`. |
| 2 | admin-only | Only processes with `CAP_SYS_PTRACE`, which in practice means root. |
| 3 | none | Nobody, including root. |

**Level 1**
- This is the default on Ubuntu and, as far as I recall, Arch.
- `strace ./prog` and `gdb ./prog` work, because you are the parent.
- `gdb -p <pid>` on an unrelated process fails without `sudo`.
- Crash handlers that call `PR_SET_PTRACER` (browsers, some game launchers) keep working.
- It does not protect the AWS CLI, because the process that launched `aws` is its parent and is allowed to attach. That is the gap the helper now requires you to close.

**Level 2**
- Besides `PTRACE_ATTACH`, it also blocks a child calling `PTRACE_TRACEME`. So a normal user can no longer run `strace ./prog` or `gdb ./prog` either, not just attach to running processes. My `docs/aws.md` text understates this, saying only that `gdb -p` and `strace -p` need `sudo`. I'd correct it.
- Debugging then needs `sudo`, or a grant of `CAP_SYS_PTRACE` to the debugger binary. Tools like `rr` and some profilers are affected too.
- It is reversible: `sysctl kernel.yama.ptrace_scope=1` as root puts it back until reboot.

**Level 3**
- Once set, it cannot be lowered until the next reboot, even by root.
- It is the strongest, but you lose all debugging and tracing, including for the admin. Both 2 and 3 satisfy the helper, so I'd use 2.

**What the setting covers**
- Yama applies to attach-style access: `PTRACE_ATTACH`, and, to my knowledge, `process_vm_readv/writev` and writing `/proc/<pid>/mem`, which use the same kernel check. That is why it also blocks the "rewrite the CLI's memory, then detach" trick.
- It does not restrict read-only inspection, such as the helper reading `/proc/<pid>/maps`, `environ` and `fd`. That is why the helper can still verify the caller at level 2.
- It does not stop root, or a process holding `CAP_SYS_PTRACE`. At levels 0 to 2, anything running as root can still read the credentials, which is outside this threat model.
- It is a host-wide kernel setting. Containers and most VMs can't change it, so there you need the waiver file or a host-side setting.

**How to set it**
```bash
cat /proc/sys/kernel/yama/ptrace_scope        # check
sudo sysctl kernel.yama.ptrace_scope=2        # until reboot
echo 'kernel.yama.ptrace_scope = 2' | sudo tee /etc/sysctl.d/99-methuselah-ptrace.conf   # persistent
```
Use the `99-` prefix because sysctl applies files in alphabetical order, and Ubuntu's own `10-ptrace.conf` would otherwise reset it to 1 at boot.
