import asyncio
import asyncssh
import re
import sys
import os
from pathlib import Path

# CDP §12.4: permanent exclusion list — IPs the broker may never block.
EXCLUSION_LIST = os.environ.get(
    "EXCLUSION_LIST",
    str(Path(__file__).resolve().parents[2] / "governance" / "exclusion_list.txt"),
)


def load_excluded_ips() -> set:
    """Read exact IPv4 entries from the canonical exclusion list."""
    ips = set()
    try:
        with open(EXCLUSION_LIST, "r", encoding="utf-8") as fh:
            for line in fh:
                entry = line.split("#", 1)[0].strip()
                if entry and re.match(r"^(?:\d{1,3}\.){3}\d{1,3}$", entry):
                    ips.add(entry)
    except OSError as e:
        print(f"[-] EXCLUSION LIST UNREADABLE ({EXCLUSION_LIST}): {e}", file=sys.stderr)
    return ips


def is_excluded_ip(attacker_ip: str) -> bool:
    return attacker_ip in load_excluded_ips()


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
            known_hosts=None  # In production, configure strict host key checking!
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
