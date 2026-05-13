# ZTrust — Launch Instructions

Everything runs on a single Debian VM. Open **four terminal windows** (or tmux panes)
and follow the steps below in order.

---

## Prerequisites (first time only)

```bash
# Install system dependencies
sudo apt update && sudo apt install -y mininet openvswitch-switch python3-pip

# Install Python dependencies
pip install -r requirements.txt

# Generate DID key pairs + blockchain ledger (creates keystore/secrets.json + ledger.json)
cd ~/Bureau/Ztrust/DID
python3 gen_did.py
```

> `keystore/secrets.json` contains private keys — never commit this file.

---

## Terminal 1 — Ryu Controller

```bash
cd ~/Bureau/Ztrust/DID
source ~/Bureau/depin_env/bin/activate
ryu-manager --observe-links did_controller.py ryu.topology.switches
```

Wait until you see `BLOCKCHAIN LOADED: 23 blocks` before starting the topology.

---

## Terminal 2 — Mininet Topology

```bash
cd ~/Bureau/Ztrust
sudo python3 topologies/topo_projet.py
```

This starts 22 switches + 22 hosts and automatically triggers DID authentication
for every switch. Within a few seconds all switches should appear as `✅ AUTH OK`
in Terminal 1.

**Useful Mininet CLI commands:**

```
mininet> pingall              # test connectivity across all hosts
mininet> h1 ping h2           # ping between specific hosts
mininet> reauth               # re-authenticate all switches (custom command)
mininet> exit                 # shut down the topology
```

---

## Terminal 3 — Web Dashboard (optional)

```bash
cd ~/Bureau/Ztrust/DID
sudo python3 dashboard_server.py
```

Open **http://localhost:8181** in a browser.

The dashboard shows:
- Live topology graph (green = authenticated, yellow = pending, grey = unknown)
- Per-switch DID, token countdown, idle time
- IP flow traces
- Quarantine / restore / re-auth controls per switch or globally
- Ping terminal (Zero Trust pre-check enforced)
- Demo mode (15 scripted scenarios)

---

## Terminal 4 — Terminal Auth Monitor (optional)

```bash
cd ~/Bureau/Ztrust/DID
python3 auth_monitor.py
```

Displays a live table of all 22 switches with their auth state and token TTL,
refreshed every second.

---

## Attack Simulation (Terminal 2 — while topology is running)

> Requires the `attack-scenarios` branch:
> ```bash
> git checkout attack-scenarios
> ```

With Ryu (Terminal 1) and Mininet (Terminal 2) both running, open a **new shell** and run:

```bash
cd ~/Bureau/Ztrust
sudo python3 DID/attack_simulation.py
```

Expected output:

```
✓ PASS  Attack 1 — Fake ECDSA signature
✓ PASS  Attack 2 — DPID spoofing / impersonation
✓ PASS  Attack 3 — Traffic injection without auth
✓ PASS  Attack 4 — Isolation (legitimate nodes)
✓ PASS  Attack 5 — Timestamp replay (stale packet)

All defenses validated — impact confined to attacked nodes.
```

Results are also saved to `/tmp/attack_results.json`.

---

## Re-generate Identities

If you need a fresh blockchain ledger (e.g. after changing the topology):

```bash
cd ~/Bureau/Ztrust/DID
rm -f ledger.json keystore/secrets.json
python3 gen_did.py
```

Then restart the Ryu controller (Terminal 1) so it reloads the new ledger.

---

## Teardown

```bash
# In Mininet terminal
mininet> exit

# Stop the controller with Ctrl+C

# Clean up OVS state if needed
sudo mn --clean
```

---

## Key File Locations at Runtime

| File | Description |
|---|---|
| `/tmp/sdn_auth_status.json` | Live auth state for all 22 switches (read by dashboard + monitor) |
| `/tmp/sdn_overhead.json` | ECDSA verification latency per auth event |
| `/tmp/mn_host_pids.json` | Mininet host PIDs (used by re-auth and attack simulation) |
| `/tmp/attack_results.json` | Last attack simulation results |
| `DID/ledger.json` | Blockchain ledger (public keys only — safe to commit) |
| `DID/keystore/secrets.json` | Private keys — **never commit** |
