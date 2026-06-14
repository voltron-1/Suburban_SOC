import asyncio
import asyncssh
import ipaddress
import sys
import os
from pathlib import Path

# CDP §12.4: permanent exclusion list — IPs the broker may never block.
def _default_exclusion_path() -> str:
    """Locate governance/exclusion_list.txt by walking up from this file.

    A fixed parents[N] breaks across layouts: in the repo this file lives at
    scripts/hive-mind-broker/, but in the container it is /app/dispatcher.py (only
    two parents) — parents[2] raised IndexError at import and crash-looped the
    broker. Walking the parents finds it in both, with a container-mount fallback.
    """
    here = Path(__file__).resolve()
    for parent in here.parents:
        candidate = parent / "governance" / "exclusion_list.txt"
        if candidate.is_file():
            return str(candidate)
    return "/governance/exclusion_list.txt"


EXCLUSION_LIST = os.environ.get("EXCLUSION_LIST") or _default_exclusion_path()

# SSH host-key verification (audit P1-3). Previously every router connection used
# known_hosts=None (no host-key checking), so a MITM on the router path could
# capture the root SSH session on the containment path. Default to verifying
# against a known_hosts file. Operators must pin the router host keys there (e.g.
# `ssh-keyscan -t ed25519 <router> >> ~/.ssh/known_hosts`). An explicit
# BROKER_INSECURE_SSH=true restores the old no-verification behaviour for a
# first-run/lab only — it logs loudly.
KNOWN_HOSTS = os.path.expanduser(
    os.environ.get("BROKER_KNOWN_HOSTS", "~/.ssh/known_hosts"))
INSECURE_SSH = os.environ.get("BROKER_INSECURE_SSH", "false").lower() == "true"


def _resolve_known_hosts():
    """Return the asyncssh `known_hosts` value: the known_hosts path (strict — the
    connection fails if the router key is unknown), or None ONLY when the operator
    explicitly opted out via BROKER_INSECURE_SSH=true."""
    if INSECURE_SSH:
        print("[!] BROKER_INSECURE_SSH=true — SSH host-key verification is DISABLED "
              "(lab/first-run only; do not use in production).", file=sys.stderr)
        return None
    return KNOWN_HOSTS


def load_excluded_ips() -> set:
    """Read IP/CIDR entries (IPv4 or IPv6, single address or network) from the
    canonical exclusion list (audit P2-7). MAC lines and junk are skipped — the
    broker blocks by IP only."""
    ips = set()
    try:
        with open(EXCLUSION_LIST, "r", encoding="utf-8") as fh:
            for line in fh:
                entry = line.split("#", 1)[0].strip()
                if not entry:
                    continue
                try:
                    ipaddress.ip_network(entry, strict=False)  # validates v4/v6/CIDR
                    ips.add(entry)
                except ValueError:
                    pass  # not an IP/CIDR (e.g. a MAC) — broker excludes by IP
    except OSError as e:
        print(f"[-] EXCLUSION LIST UNREADABLE ({EXCLUSION_LIST}): {e}", file=sys.stderr)
    return ips


def is_excluded_ip(attacker_ip: str) -> bool:
    """True if attacker_ip falls inside any excluded address/CIDR (v4 or v6)."""
    try:
        addr = ipaddress.ip_address(attacker_ip)
    except ValueError:
        return False
    for entry in load_excluded_ips():
        try:
            if addr in ipaddress.ip_network(entry, strict=False):
                return True
        except ValueError:
            continue
    return False


# Formulate the nftables drop command (Task 2.2.1)
# Drops traffic from the specified IP on the OpenWrt input chain.
# Note: For OpenWrt 22.03+, we assume 'inet fw4 input' is the default target chain.
def build_nft_command(attacker_ip: str) -> str:
    return f"nft add rule inet fw4 input ip saddr {attacker_ip} drop"

async def block_ip_on_router(router: dict, attacker_ip: str):
    """
    Connects to a single router and executes the block command. (Task 2.1.1 & 2.2.2)
    """
    ip = router.get("ip_address")
    username = router.get("username", "root")
    key_path = os.path.expanduser(router.get("ssh_key_path", "~/.ssh/id_ed25519_hivemind"))
    
    command = build_nft_command(attacker_ip)
    
    try:
        # Connect asynchronously
        async with asyncssh.connect(
            host=ip,
            username=username,
            client_keys=[key_path],
            known_hosts=_resolve_known_hosts()  # strict by default (audit P1-3)
        ) as conn:
            
            # Execute command
            await conn.run(command, check=True)
            print(f"[+] Successfully blocked {attacker_ip} on {ip}")
            return True
            
    except asyncssh.Error as exc:
        print(f"[-] SSH connection failed to {ip}: {str(exc)}", file=sys.stderr)
        return False
    except Exception as e:
        print(f"[-] Error executing on {ip}: {str(e)}", file=sys.stderr)
        return False

async def dispatch_block_to_all(routers: list, attacker_ip: str):
    """
    Loops through the inventory and fires concurrent SSH block commands. (Task 2.1.2)
    """
    # §12.4: never push a block for a protected asset, even if an alert demands it.
    if is_excluded_ip(attacker_ip):
        print(f"[!] REFUSED: {attacker_ip} is on the permanent exclusion list — no block dispatched.",
              file=sys.stderr)
        return 0

    print(f"[*] Dispatching block for {attacker_ip} to {len(routers)} routers...")

    # Create a list of async tasks for all routers
    tasks = [block_ip_on_router(r, attacker_ip) for r in routers]
    
    # Run them concurrently (acting as a parallel connection pool)
    results = await asyncio.gather(*tasks)
    
    success_count = sum(1 for r in results if r)
    print(f"[*] Immunization complete: {success_count}/{len(routers)} routers updated.")
    return success_count
