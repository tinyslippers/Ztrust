from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController, OVSKernelSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel
from time import sleep
import os
import json

AGENT_PATH = '/home/debian/Bureau/DID/agent_auth.py'

class CustomCLI(CLI):
    def do_reauth(self, _line):
        """Re-authenticates all DID switches: reauth"""
        print("\n--- Re-authenticating all switches ---")
        for i in range(1, 23):
            h = self.mn.get(f'h{i}')
            h.cmd(f'python3 {AGENT_PATH} switch_{i} > /dev/null 2>&1')
            print(f'  switch_{i} re-authenticated')
            sleep(0.3)
        print("All switches re-authenticated.\n")

class HandDrawnTopo(Topo):
    def build(self):
        print("🏗️  Creating 22 switches (Option B layout)...")

        # 1. Create switches
        s = {}
        for i in range(1, 23):
            # STP disabled: Ryu manages topology via OpenFlow (Dijkstra)
            s[i] = self.addSwitch(f's{i}', protocols='OpenFlow13', failMode='secure')

        # 2. Manual wiring (updated with CSV)
        print("🔗  Complex wiring (Mesh Topology)...")

        links = [
            # Top-Left branch
            (1, 2), (2, 3), (2, 4), (4, 5), (1, 5),

            # --- CSV additions (Option B) ---
            (1, 4),   # Direct connection S1-S4
            (1, 6),   # Direct connection S1-S6
            (2, 21),  # Bridge between Top-Left and Far-Left branch
            (11, 17), # Bridge between Bottom-Right and Bottom-Left (closes the bottom loop)
            # --------------------------------

            # Top-Right branch
            (5, 6), (6, 7), (1, 7), (7, 8),

            # Right branch
            (7, 9), (9, 10), (1, 9),

            # Bottom-Right branch
            (9, 11), (11, 12), (11, 13), (1, 11),

            # Bottom-Far branch
            (11, 14), (14, 15), (15, 16),

            # Bottom-Left branch
            (1, 17), (17, 18), (17, 19),

            # Left branch
            (19, 20), (20, 1),

            # Far-Top-Left branch
            (20, 21), (21, 22), (21, 1)
        ]

        for (src, dst) in links:
            self.addLink(s[src], s[dst])

        # 3. Create hosts
        print("💻  Creating hosts (h1...h22)...")
        for i in range(1, 23):
            mac_addr = '00:00:00:00:00:{:02x}'.format(i)
            ip_addr = '10.0.0.{}'.format(i)
            h = self.addHost(f'h{i}', mac=mac_addr, ip=ip_addr)
            self.addLink(h, s[i])

def automated_run():
    # Preventive cleanup
    os.system('sudo mn -c > /dev/null 2>&1')

    topo = HandDrawnTopo()
    # Remote controller (Ryu)
    net = Mininet(topo=topo, controller=RemoteController, switch=OVSKernelSwitch)

    print("\n--- 🚀 STARTING COMPLEX TOPOLOGY (Zero Trust) ---")
    net.start()

    # Wait for network convergence (LLDP discovery by Ryu)
    print("⏳ Waiting for network convergence (8s)...")
    sleep(8)

    # Save host PIDs for the dashboard (individual re-auth)
    pids = {str(i): net.get(f'h{i}').pid for i in range(1, 23)}
    with open('/tmp/mn_host_pids.json', 'w') as f:
        json.dump(pids, f)
    print("Host PIDs saved to /tmp/mn_host_pids.json")

    # --- Static ARP configuration for all hosts ---
    print("\n--- Injecting ARP tables (all hosts) ---")
    for i in range(1, 23):
        h = net.get(f'h{i}')
        for j in range(1, 23):
            if i != j:
                mac = '00:00:00:00:00:{:02x}'.format(j)
                h.cmd(f'arp -s 10.0.0.{j} {mac}')

    # --- Automatic DID authentication ---
    print("\n--- DID authentication for all switches ---")
    agent_path = AGENT_PATH
    for i in range(1, 23):
        h = net.get(f'h{i}')
        h.cmd(f'python3 {agent_path} switch_{i} > /dev/null 2>&1')
        print(f"  switch_{i} authenticated")
        sleep(0.5)
    print("All switches authenticated.")

    # --- Start watchdog agents (autonomous re-auth every 25 min) ---
    print("\n--- Starting watchdog agents ---")
    for i in range(1, 23):
        h = net.get(f'h{i}')
        h.cmd(f'python3 {agent_path} switch_{i} --watchdog > /dev/null 2>&1 &')
    print("Watchdogs active on all 22 hosts (interval: 25 min).")

    # --- Start Monitor ---
    current_dir = os.path.dirname(os.path.abspath(__file__))
    monitor_path = os.path.join(current_dir, "monitor.py")
    if os.path.exists(monitor_path):
        cmd = f"setsid xterm -T 'WATCHDOG MONITOR' -geometry 90x10+0+0 -hold -e 'sudo python3 {monitor_path}' &"
        os.system(cmd)
        print(f"Monitor launched.")

    print("\n" + "="*50)
    print("TOPOLOGY LOADED + DID AUTH COMPLETE")
    print("="*50)

    CustomCLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    automated_run()
