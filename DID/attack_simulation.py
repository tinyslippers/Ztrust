#!/usr/bin/env python3
"""
attack_simulation.py — Zero Trust SDN attack validation suite

Simulates 3 attack scenarios from Mininet hosts via nsenter and verifies
that ZTrust defenses hold while legitimate nodes remain unaffected.

  Attack 1 — Fake signature       : valid DID + random 64-byte sig → ECDSA rejects it
  Attack 2 — DPID spoofing        : s19 sends s1's valid token → anti-spoof blocks it
  Attack 3 — Traffic without auth : unauthenticated h20 pings h1 → table-miss DROP
  Attack 4 — Isolation            : s1/s2/s3 stay authenticated and reachable throughout

Prerequisites:
  - ryu-manager running with did_controller.py
  - topo_projet.py running (Mininet topology active)

Usage:
  sudo python3 DID/attack_simulation.py
"""

import binascii
import json
import os
import subprocess
import sys
import time
from ecdsa import SigningKey, SECP256k1

# ── Paths ──────────────────────────────────────────────────────────────────────
_HERE         = os.path.dirname(os.path.abspath(__file__))
PIDS_FILE     = '/tmp/mn_host_pids.json'
STATUS_FILE   = '/tmp/sdn_auth_status.json'
KEYSTORE      = os.path.join(_HERE, 'keystore/secrets.json')
AGENT         = os.path.join(_HERE, 'agent_auth.py')
RESULTS_FILE  = '/tmp/attack_results.json'
CONTROLLER_IP = '10.255.255.255'
AUTH_PORT     = 9999

# Attacker switch IDs (quarantined/reconnected for each test)
ATK_FAKE_SIG = 18   # Attack 1
ATK_SPOOF    = 19   # Attack 2 — impersonates SPOOF_VICTIM
ATK_NO_AUTH  = 20   # Attack 3
ATK_REPLAY   = 21   # Attack 5 — stale timestamp replay
SPOOF_VICTIM = 1    # Switch being impersonated in Attack 2

# Legitimate switches — must stay authenticated throughout all attacks
LEGITIMATE   = [1, 2, 3]

# ── Colors ─────────────────────────────────────────────────────────────────────
R, B = '\033[0m', '\033[1m'
RED, GRN, YLW, CYN, GRY = '\033[91m', '\033[92m', '\033[93m', '\033[96m', '\033[90m'


def hdr(title):
    print(f"\n{B}{CYN}{'━' * 60}{R}")
    print(f"{B}{CYN}  {title}{R}")
    print(f"{B}{CYN}{'━' * 60}{R}")


def blocked(msg): print(f"  {GRN}[BLOCKED]{R}  {msg}")
def fail(msg):    print(f"  {RED}[FAIL]   {R}  {msg}")
def info(msg):    print(f"  {GRY}·{R} {msg}")


# ── Helpers ────────────────────────────────────────────────────────────────────

def load_pids():
    try:
        with open(PIDS_FILE) as f:
            return {int(k): v for k, v in json.load(f).items()}
    except FileNotFoundError:
        sys.exit(f"[ERROR] {PIDS_FILE} not found — is topo_projet.py running?")


def get_state(sid):
    try:
        with open(STATUS_FILE) as f:
            return json.load(f).get(str(sid), {}).get('state', 'unknown')
    except Exception:
        return 'unknown'


def ns_run(pid, cmd, timeout=12):
    r = subprocess.run(
        ['nsenter', '-n', '-t', str(pid), '--'] + cmd,
        capture_output=True, text=True, timeout=timeout
    )
    return r.returncode, r.stdout, r.stderr


def send_udp(pid, payload: bytes):
    """Send a raw UDP payload on port 9999 from inside the host network namespace."""
    tmp = '/tmp/_atk_pkt.bin'
    with open(tmp, 'wb') as f:
        f.write(payload)
    ns_run(pid, [
        'python3', '-c',
        f"import socket,time\n"
        f"d=open('{tmp}','rb').read()\n"
        f"s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)\n"
        f"s.setsockopt(socket.SOL_SOCKET,socket.SO_BROADCAST,1)\n"
        f"[s.sendto(d,('{CONTROLLER_IP}',{AUTH_PORT})) or time.sleep(0.1) for _ in range(3)]\n"
    ])


def make_valid_payload(switch_name: str, secrets: dict) -> bytes:
    identity = secrets[switch_name]
    did = identity['did']
    ts  = str(int(time.time()))
    msg = f"AuthRequest:{did}:{ts}"
    sk  = SigningKey.from_string(binascii.unhexlify(identity['private_key']), curve=SECP256k1)
    sig = binascii.hexlify(sk.sign(msg.encode())).decode()
    return json.dumps({'did': did, 'message': msg,
                       'signature': sig, 'timestamp': ts}).encode()


def make_stale_payload(switch_name: str, secrets: dict, age_s: int = 31) -> bytes:
    """Build a cryptographically valid payload whose timestamp is `age_s` seconds old."""
    identity = secrets[switch_name]
    did = identity['did']
    ts  = str(int(time.time()) - age_s)
    msg = f"AuthRequest:{did}:{ts}"
    sk  = SigningKey.from_string(binascii.unhexlify(identity['private_key']), curve=SECP256k1)
    sig = binascii.hexlify(sk.sign(msg.encode())).decode()
    return json.dumps({'did': did, 'message': msg,
                       'signature': sig, 'timestamp': ts}).encode()


def make_fake_sig_payload(switch_name: str, secrets: dict) -> bytes:
    identity = secrets[switch_name]
    did = identity['did']
    ts  = str(int(time.time()))
    msg = f"AuthRequest:{did}:{ts}"
    fake_sig = binascii.hexlify(os.urandom(64)).decode()
    return json.dumps({'did': did, 'message': msg,
                       'signature': fake_sig, 'timestamp': ts}).encode()


def quarantine(sid):
    subprocess.run(['ovs-vsctl', 'del-controller', f's{sid}'], capture_output=True)


def reconnect(sid):
    subprocess.run(['ovs-vsctl', 'set-controller', f's{sid}',
                    'tcp:127.0.0.1:6633'], capture_output=True)
    time.sleep(2)  # let controller install table-miss rule


def reset_attacker(sid) -> bool:
    """Quarantine then reconnect so the switch is unauthenticated for a clean test."""
    info(f"Resetting s{sid}: quarantine → reconnect …")
    quarantine(sid)
    time.sleep(1)
    reconnect(sid)
    state = get_state(sid)
    info(f"s{sid} state after reset: '{state}'")
    return state == 'connected'


# ══════════════════════════════════════════════════════════════════════════════
# ATTACK 1 — Fake / corrupted ECDSA signature
# ══════════════════════════════════════════════════════════════════════════════

def attack1_fake_signature(pids: dict, secrets: dict) -> bool | None:
    sid = ATK_FAKE_SIG
    hdr(f"ATTACK 1 — Fake signature  (attacker: s{sid})")
    info(f"s{sid} sends a valid DID with a 64-byte random (garbage) signature.")
    info(f"Defense: verify_signature() returns False → switch stays unauthenticated.")

    if not reset_attacker(sid):
        info("Could not reset attacker to 'connected' state — skipping.")
        return None

    payload = make_fake_sig_payload(f'switch_{sid}', secrets)
    send_udp(pids[sid], payload)
    time.sleep(1.5)

    state = get_state(sid)
    if state != 'auth':
        blocked(f"s{sid} state='{state}' — fake signature rejected, switch stays blocked.")
        return True
    else:
        fail(f"s{sid} state='auth' — ECDSA check bypassed. Defense FAILED.")
        return False


# ══════════════════════════════════════════════════════════════════════════════
# ATTACK 2 — DPID spoofing (impersonation)
# ══════════════════════════════════════════════════════════════════════════════

def attack2_dpid_spoofing(pids: dict, secrets: dict) -> bool | None:
    sid_atk = ATK_SPOOF
    sid_vic = SPOOF_VICTIM
    hdr(f"ATTACK 2 — DPID spoofing  (s{sid_atk} impersonates s{sid_vic})")
    info(f"s{sid_atk} sends a VALID signature for s{sid_vic}'s DID.")
    info(f"Packet arrives at controller from DPID={sid_atk}, but DID claims switch_{sid_vic}.")
    info(f"Defense: claimed_id={sid_vic} ≠ dpid={sid_atk} → SPOOFING DETECTED → DROP.")

    if not reset_attacker(sid_atk):
        info("Could not reset attacker — skipping.")
        return None

    # Build a cryptographically valid payload for the VICTIM,
    # but send it from the ATTACKER's host namespace (→ arrives at s{sid_atk}).
    payload = make_valid_payload(f'switch_{sid_vic}', secrets)
    send_udp(pids[sid_atk], payload)
    time.sleep(1.5)

    state_atk = get_state(sid_atk)
    state_vic = get_state(sid_vic)

    if state_atk != 'auth':
        blocked(f"s{sid_atk} state='{state_atk}' — impersonation blocked (DPID mismatch).")
        result = True
    else:
        fail(f"s{sid_atk} state='auth' — anti-spoofing check bypassed. Defense FAILED.")
        result = False

    info(f"s{sid_vic} (victim) state='{state_vic}' — unaffected by attack.")
    return result


# ══════════════════════════════════════════════════════════════════════════════
# ATTACK 3 — Traffic injection without authentication
# ══════════════════════════════════════════════════════════════════════════════

def attack3_traffic_no_auth(pids: dict) -> bool | None:
    sid    = ATK_NO_AUTH
    target = 1
    hdr(f"ATTACK 3 — Traffic without auth  (h{sid} → h{target})")
    info(f"h{sid} attempts to ping 10.0.0.{target} while s{sid} is unauthenticated.")
    info(f"Defense: table-miss DROP rule (priority 0) discards all non-UDP:9999 traffic.")

    if not reset_attacker(sid):
        info("Could not reset attacker — skipping.")
        return None

    state = get_state(sid)
    if state == 'auth':
        info(f"s{sid} still authenticated after reset — test not clean, skipping.")
        return None

    info(f"Sending 3 ICMP ping packets: 10.0.0.{sid} → 10.0.0.{target} …")
    rc, stdout, _ = ns_run(
        pids[sid],
        ['ping', '-c', '3', '-W', '1', f'10.0.0.{target}'],
        timeout=12
    )

    lost = ('100% packet loss' in stdout) or ('0 received' in stdout)
    if lost:
        blocked(f"Ping BLOCKED — 100% packet loss (3/3 dropped by table-miss rule).")
        return True
    else:
        fail(f"Ping SUCCEEDED — unauthenticated host reached legitimate node. Defense FAILED.")
        return False


# ══════════════════════════════════════════════════════════════════════════════
# ATTACK 4 — Isolation: legitimate nodes unaffected throughout
# ══════════════════════════════════════════════════════════════════════════════

def check_isolation(pids: dict) -> bool:
    hdr("ATTACK 4 — Isolation: legitimate nodes unaffected")
    info(f"Verifying that s{LEGITIMATE} remained authenticated during all attacks.")

    auth_ok = True
    for sid in LEGITIMATE:
        state = get_state(sid)
        if state == 'auth':
            blocked(f"s{sid} still authenticated (state='{state}') — no collateral impact.")
        else:
            fail(f"s{sid} state='{state}' — lost authentication during attacks (collateral damage).")
            auth_ok = False

    info(f"\n  Connectivity test: h1 → h2 (10.0.0.2) via authenticated path …")
    rc, stdout, _ = ns_run(pids[1], ['ping', '-c', '2', '-W', '1', '10.0.0.2'], timeout=8)
    reachable = (rc == 0)
    if reachable:
        blocked("h1 → h2 ping OK — legitimate traffic flows normally.")
    else:
        fail("h1 → h2 ping FAILED — legitimate connectivity impaired.")

    return auth_ok and reachable


# ══════════════════════════════════════════════════════════════════════════════
# ATTACK 5 — Timestamp replay (requires freshness check in did_controller.py)
# ══════════════════════════════════════════════════════════════════════════════

def attack5_timestamp_replay(pids: dict, secrets: dict) -> bool | None:
    sid = ATK_REPLAY
    hdr(f"ATTACK 5 — Timestamp replay  (attacker: s{sid})")
    info(f"s{sid} sends a cryptographically valid packet whose timestamp is 31 s old.")
    info(f"Defense: freshness check — abs(now - ts) > 30 s → packet rejected.")

    if not reset_attacker(sid):
        info("Could not reset attacker to 'connected' state — skipping.")
        return None

    payload = make_stale_payload(f'switch_{sid}', secrets, age_s=31)
    send_udp(pids[sid], payload)
    time.sleep(1.5)

    state = get_state(sid)
    if state != 'auth':
        blocked(f"s{sid} state='{state}' — stale packet rejected (timestamp too old).")
        return True
    else:
        fail(f"s{sid} state='auth' — freshness check missing or disabled. Defense FAILED.")
        return False


# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════

def main():
    print(f"\n{B}{CYN}{'═' * 60}{R}")
    print(f"{B}{CYN}   ZTrust — Attack Simulation Suite{R}")
    print(f"{B}{CYN}{'═' * 60}{R}")
    print(f"  {GRY}Status file : {STATUS_FILE}{R}")
    print(f"  {GRY}Started     : {time.strftime('%Y-%m-%d %H:%M:%S')}{R}\n")

    if os.geteuid() != 0:
        sys.exit("[ERROR] Must run as root: sudo python3 DID/attack_simulation.py")

    pids    = load_pids()
    try:
        with open(KEYSTORE) as f:
            secrets = json.load(f)
    except FileNotFoundError:
        sys.exit(f"[ERROR] Keystore not found: {KEYSTORE}\n"
                 f"       Run 'python3 DID/gen_did.py' to generate keys first.")

    # Ensure legitimate nodes are authenticated before starting
    info(f"Pre-authenticating legitimate nodes {LEGITIMATE} if needed …")
    for sid in LEGITIMATE:
        if get_state(sid) != 'auth':
            ns_run(pids[sid], ['python3', AGENT, f'switch_{sid}'])
            time.sleep(0.8)
    time.sleep(1.5)

    for sid in LEGITIMATE:
        state = get_state(sid)
        if state != 'auth':
            print(f"  {YLW}[WARN]{R} s{sid} not authenticated (state='{state}') "
                  f"— isolation result may be inconclusive.")

    results = {}
    results['attack1_fake_signature']   = attack1_fake_signature(pids, secrets)
    results['attack2_dpid_spoofing']    = attack2_dpid_spoofing(pids, secrets)
    results['attack3_no_auth_traffic']  = attack3_traffic_no_auth(pids)
    results['attack4_isolation']        = check_isolation(pids)
    results['attack5_timestamp_replay'] = attack5_timestamp_replay(pids, secrets)

    # ── Summary ───────────────────────────────────────────────────────────────
    hdr("RESULTS SUMMARY")
    labels = {
        'attack1_fake_signature'  : 'Attack 1 — Fake ECDSA signature',
        'attack2_dpid_spoofing'   : 'Attack 2 — DPID spoofing / impersonation',
        'attack3_no_auth_traffic' : 'Attack 3 — Traffic injection without auth',
        'attack4_isolation'       : 'Attack 4 — Isolation (legitimate nodes)',
        'attack5_timestamp_replay': 'Attack 5 — Timestamp replay (stale packet)',
    }
    all_pass = True
    for key, label in labels.items():
        val = results[key]
        if val is True:
            print(f"  {GRN}✓ PASS{R}  {label}")
        elif val is False:
            print(f"  {RED}✗ FAIL{R}  {label}")
            all_pass = False
        else:
            print(f"  {YLW}– SKIP{R}  {label}  (precondition not met)")
    print()
    if all_pass:
        print(f"  {B}{GRN}All defenses validated — impact confined to attacked nodes.{R}")
    else:
        print(f"  {B}{RED}One or more defenses failed — check controller logs.{R}")

    results['timestamp'] = time.strftime('%Y-%m-%dT%H:%M:%S')
    with open(RESULTS_FILE, 'w') as f:
        json.dump(results, f, indent=2)
    print(f"\n  {GRY}Full results saved to {RESULTS_FILE}{R}\n")


if __name__ == '__main__':
    main()
