# sandbox/syscall_parser.py

import re

SUSPICIOUS_SYSCALLS = {
    "network": ["connect", "sendto", "recvfrom"],
    "file_modification": ["open", "write", "unlink"],
    "process_injection": ["ptrace"],
    "privilege": ["setuid", "setgid"],
    "execution": ["execve"],
}

def parse_syscalls(strace_output):
    findings = {
        "network": 0,
        "file_modification": 0,
        "process_injection": 0,
        "privilege": 0,
        "execution": 0
    }

    for line in strace_output.splitlines():
        for category, calls in SUSPICIOUS_SYSCALLS.items():
            for call in calls:
                if re.search(rf"\b{call}\(", line):
                    findings[category] += 1

    return findings
