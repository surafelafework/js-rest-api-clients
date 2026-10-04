#!/usr/bin/env python3
"""
xfrm_lpe_audit.py - assess whether a host exposes the preconditions
for page-cache / XFRM-class local privilege escalation.

Read-only. Does not configure anything. Safe to run anywhere.
"""

import os
import re
import platform
import subprocess
import glob

def sh(cmd):
    try:
        return subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=5
        ).stdout.strip()
    except Exception:
        return ""

def kernel_version():
    rel = platform.release()
    m = re.match(r"(\d+)\.(\d+)(?:\.(\d+))?", rel)
    if not m:
        return rel, None
    return rel, tuple(int(x) if x else 0 for x in m.groups())

def kernel_config():
    """Return dict of CONFIG_* -> value from the running kernel's config."""
    cfg = {}
    candidates = [
        f"/boot/config-{platform.release()}",
        "/proc/config.gz",
        "/boot/config",
    ]
    for path in candidates:
        if not os.path.exists(path):
            continue
        try:
            if path.endswith(".gz"):
                import gzip
                data = gzip.open(path, "rt", errors="replace").read()
            else:
                data = open(path, "r", errors="replace").read()
        except Exception:
            continue
        for line in data.splitlines():
            line = line.strip()
            if line.startswith("CONFIG_") and "=" in line:
                k, v = line.split("=", 1)
                cfg[k] = v
        if cfg:
            break
    return cfg

def check_userns():
    """Is unprivileged user namespace creation allowed?"""
    path = "/proc/sys/kernel/unprivileged_userns_clone"
    if os.path.exists(path):
        try:
            return open(path).read().strip() == "1"
        except Exception:
            return None
    # Debian/Ubuntu variant, or the sysctl simply doesn't exist
    val = sh("sysctl -n kernel.unprivileged_userns_clone 2>/dev/null")
    if val in ("0", "1"):
        return val == "1"
    # Newer kernels: knob is user.max_user_namespaces
    val = sh("sysctl -n user.max_user_namespaces 2>/dev/null")
    if val.isdigit():
        return int(val) > 0
    return None

def check_apparmor_userns_restrict():
    """Ubuntu restricts unprivileged userns via AppArmor in some releases."""
    path = "/proc/sys/kernel/apparmor_restrict_unprivileged_userns"
    if os.path.exists(path):
        try:
            return open(path).read().strip() == "1"
        except Exception:
            return None
    return None

def check_fsverity_and_ima(cfg):
    """fs-verity / IMA detect tampering with mapped executables."""
    return {
        "CONFIG_FS_VERITY": cfg.get("CONFIG_FS_VERITY"),
        "CONFIG_IMA": cfg.get("CONFIG_IMA"),
        "CONFIG_IMA_APPRAISE": cfg.get("CONFIG_IMA_APPRAISE"),
        "CONFIG_IMA_APPRAISE_BOOTPARAM": cfg.get("CONFIG_IMA_APPRAISE_BOOTPARAM"),
    }

def check_selinux():
    enforce = "/sys/fs/selinux/enforce"
    if os.path.exists(enforce):
        try:
            return open(enforce).read().strip() == "1"
        except Exception:
            return None
    return None

def suid_binaries():
    out = sh(
        "find / -xdev -perm -4000 -type f 2>/dev/null | head -50"
    )
    return [l for l in out.splitlines() if l.strip()]

def main():
    print("=" * 68)
    print("XFRM / page-cache LPE precondition audit")
    print("=" * 68)

    rel, ver = kernel_version()
    print(f"\nKernel release : {rel}")
    if ver:
        print(f"Parsed version : {ver[0]}.{ver[1]}.{ver[2]}")

    cfg = kernel_config()
    print(f"\nKernel config  : {'found' if cfg else 'NOT AVAILABLE'}")

    if cfg:
        interesting = [
            "CONFIG_XFRM",
            "CONFIG_XFRM_USER",
            "CONFIG_INET_ESP",
            "CONFIG_INET6_ESP",
            "CONFIG_NETFILTER_XT_TARGET_TEE",
            "CONFIG_USER_NS",
            "CONFIG_NET_NS",
            "CONFIG_SECURITY",
            "CONFIG_SECURITY_APPARMOR",
        ]
        print("\n-- Relevant kernel options --")
        for k in interesting:
            v = cfg.get(k, "(not set)")
            print(f"  {k:<42} {v}")

    print("\n-- Attack-surface knobs --")
    userns = check_userns()
    print(f"  unprivileged user namespaces allowed : {userns}")
    aa = check_apparmor_userns_restrict()
    print(f"  AppArmor userns restriction active   : {aa}")
    se = check_selinux()
    print(f"  SELinux enforcing                    : {se}")

    print("\n-- Integrity / tamper-detection --")
    for k, v in check_fsverity_and_ima(cfg).items():
        print(f"  {k:<36} {v if v is not None else '(unknown)'}")

    print("\n-- SUID binaries on this system (first 50) --")
    bins = suid_binaries()
    if bins:
        for b in bins:
            print(f"  {b}")
    else:
        print("  none found / find unavailable")

    # --- verdict ---
    print("\n" + "=" * 68)
    print("Assessment")
    print("=" * 68)

    xfrm = cfg.get("CONFIG_XFRM") == "y" or cfg.get("CONFIG_XFRM") == "m"
    tee = cfg.get("CONFIG_NETFILTER_XT_TARGET_TEE") in ("y", "m")
    userns_ok = userns is True

    risk = 0
    if userns_ok:
        risk += 1
        print("[+] Unprivileged user namespaces are enabled.")
        print("    -> An unprivileged process can obtain CAP_NET_ADMIN in its")
        print("       own netns, and can therefore configure XFRM and netfilter.")
    elif userns is False:
        print("[+] Unprivileged user namespaces are disabled.")
        print("    -> This alone blocks the usual setup path for this exploit class.")
    else:
        print("[?] Could not determine user-namespace policy.")

    if xfrm:
        print("[+] XFRM is compiled in.")
    else:
        print("[+] XFRM is not compiled in (or config unavailable).")

    if tee:
        print("[!] NETFILTER_XT_TARGET_TEE is available.")
        print("    -> Consider whether you need the TEE target at all. It is")
        print("       rarely used outside traffic-mirroring setups.")
    elif cfg:
        print("[+] TEE target not built.")

    if not userns_ok:
        print("\nVerdict: the standard unprivileged setup path is closed.")
    elif xfrm and tee:
        print("\nVerdict: the feature combination this exploit class needs is")
        print("         present. Patch level is the deciding factor.")
    else:
        print("\nVerdict: some prerequisites are missing; exploitability depends")
        print("         on the exact kernel revision and build options.")

    print("\nNote: this script only inspects configuration. It cannot tell you")
    print("whether a given kernel build is patched. That requires the patch")
    print("to be identified in the distribution's changelog or by testing in")
    print("an isolated lab.")

if __name__ == "__main__":
    main()
