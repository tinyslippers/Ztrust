#!/usr/bin/env python3
"""
DID Controller v2 - Zero Trust + Dynamic Topology Routing

Features:
  - DID / Blockchain authentication (Zero Trust): each switch must prove
    its identity before being allowed to forward traffic.
  - Topology discovery via LLDP (ryu.topology.switches app).
  - Route computation via Dijkstra (NetworkX).
  - Automatic recomputation when a switch or link goes down.

Usage:
  cd ~/Bureau/DID
  source ../depin_env/bin/activate
  ryu-manager --observe-links did_controller.py ryu.topology.switches
"""

import json
import binascii
import time
import os
import subprocess
from ecdsa import VerifyingKey, SECP256k1, BadSignatureError
import networkx as nx

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import (CONFIG_DISPATCHER, MAIN_DISPATCHER,
                                     DEAD_DISPATCHER, set_ev_cls)
from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub
from ryu.lib.packet import packet, ethernet, ether_types, udp, ipv4
from ryu.topology import event as topo_event

from blockchain import Blockchain

# Cookie used to tag routing rules (allows purging them
# without touching the table-miss rule which has cookie=0)
ROUTING_COOKIE     = 0xDEAD1
AUTH_PORT          = 9999
STATUS_FILE        = '/tmp/sdn_auth_status.json'
PIDS_FILE          = '/tmp/mn_host_pids.json'
AGENT_PATH         = '/home/debian/Bureau/DID/agent_auth.py'
AUTH_LIFETIME      = 1800  # Token lifetime (seconds) — 30 min
INACTIVITY_TIMEOUT = 300   # Quarantine if no packet received for X seconds
CHECK_INTERVAL     = 15    # Expiration check interval (seconds)
REAUTH_THRESHOLD   = 300   # Proactive re-auth if token expires in less than X seconds
OVERHEAD_FILE      = '/tmp/sdn_overhead.json'  # ECDSA overhead measurements
NUM_SWITCHES       = 22

# ANSI color codes for terminal output
class C:
    R  = '\033[0m'    # Reset
    B  = '\033[1m'    # Bold
    RED= '\033[91m'   # Red
    GRN= '\033[92m'   # Green
    YLW= '\033[93m'   # Yellow
    BLU= '\033[94m'   # Blue
    MAG= '\033[95m'   # Magenta
    CYN= '\033[96m'   # Cyan
    GRY= '\033[90m'   # Grey
    WHT= '\033[97m'   # White


class DIDController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(DIDController, self).__init__(*args, **kwargs)

        # --- DID / Zero Trust ---
        self.authenticated_dpid = set()   # Switches that passed DID auth
        self.dpid_to_did = {}             # {dpid: did_string}
        self.auth_expiry = {}             # {dpid: token expiration timestamp}
        self.last_seen   = {}             # {dpid: last packet timestamp}
        self.reauth_pending = set()       # Switches with proactive re-auth in progress
        self.did_documents  = {}          # {dpid: full W3C DID Document}
        self.recent_flows = []            # Recent IP flows (for the dashboard)
        self.flow_seq     = 0             # Monotonic flow counter

        try:
            self.ledger = Blockchain("ledger.json")
            self.logger.info("BLOCKCHAIN LOADED: %d blocks", len(self.ledger.chain))
        except Exception as e:
            self.logger.error("Blockchain load error: %s", e)
            self.ledger = None

        # --- Topology & Routing ---
        self.net = nx.DiGraph()   # Nodes = dpid, edges = links with 'port' attribute
        self.hosts = {}           # {mac: (dpid, port)} - host location map
        self.datapaths = {}       # {dpid: datapath}

        # --- Expiration monitoring thread ---
        self.monitor_thread = hub.spawn(self._expiry_monitor)

        self._write_status()

    # =========================================================================
    # DATAPATH MANAGEMENT
    # =========================================================================

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        self.datapaths[datapath.id] = datapath
        self._install_table_miss(datapath)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            dpid = datapath.id
            self.datapaths.pop(dpid, None)
            # Immediately clean auth state to avoid the window between
            # DEAD_DISPATCHER and EventSwitchLeave where the switch stays 'auth'
            if dpid in self.authenticated_dpid:
                self.authenticated_dpid.discard(dpid)
                self.dpid_to_did.pop(dpid, None)
                self.auth_expiry.pop(dpid, None)
                self.last_seen.pop(dpid, None)
                self.reauth_pending.discard(dpid)
                self.did_documents.pop(dpid, None)
                self._write_status()

    def _install_table_miss(self, datapath):
        """Priority 0 rule: any packet with no matching rule → sent to controller."""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self._add_flow(datapath, priority=0, match=match, actions=actions, cookie=0)

    # =========================================================================
    # DID AUTHENTICATION (Zero Trust)
    # =========================================================================

    def verify_signature(self, did, message, signature_hex):
        """Verifies the ECDSA signature of a switch via W3C DID Document resolution."""
        if not self.ledger:
            return False
        did_doc = self.ledger.resolve(did)
        if not did_doc:
            self.logger.warning("DID not found or revoked: %s", did)
            return False
        pub_key_hex = None
        for method in did_doc.get("verificationMethod", []):
            if "keys-1" in method.get("id", ""):
                pub_key_hex = method.get("publicKeyHex")
                break
        if not pub_key_hex:
            return False
        try:
            vk = VerifyingKey.from_string(binascii.unhexlify(pub_key_hex),
                                          curve=SECP256k1)
            return vk.verify(binascii.unhexlify(signature_hex),
                             message.encode('utf-8'))
        except (BadSignatureError, binascii.Error) as e:
            self.logger.error("Signature verification failed: %s", e)
            return False

    def _handle_auth_packet(self, dpid, msg):
        """Handles a DID authentication packet (UDP port 9999)."""
        try:
            full_data_str = msg.data.decode('utf-8', errors='ignore')
            start = full_data_str.find('{')
            end = full_data_str.rfind('}') + 1
            if start == -1 or end == 0:
                self.logger.warning("UDP 9999 packet received but no valid JSON found.")
                return

            data = json.loads(full_data_str[start:end])
            did = data.get('did')
            sig = data.get('signature')
            msg_content = data.get('message')

            # Timestamp freshness check (anti-replay: reject packets older than 30 s)
            ts = data.get('timestamp')
            if ts is None or abs(time.time() - float(ts)) > 30:
                self.logger.warning("Auth packet rejected — stale timestamp (dpid=%s)", dpid)
                return

            # 1. Cryptographic verification (ECDSA signature) — overhead measurement
            t_auth_start = time.time()
            if not self.verify_signature(did, msg_content, sig):
                self.logger.warning("Signature FAILED for switch dpid=%s", dpid)
                return
            t_ecdsa_ms = (time.time() - t_auth_start) * 1000

            # Store overhead measurement in JSON file
            try:
                try:
                    with open(OVERHEAD_FILE) as f:
                        overhead_data = json.load(f)
                except (FileNotFoundError, json.JSONDecodeError):
                    overhead_data = []
                overhead_data.append({
                    'dpid'     : dpid,
                    'did'      : did,
                    'ecdsa_ms' : round(t_ecdsa_ms, 3),
                    'type'     : 'reauth' if dpid in self.authenticated_dpid else 'auth',
                    'timestamp': round(time.time(), 2)
                })
                with open(OVERHEAD_FILE, 'w') as f:
                    json.dump(overhead_data, f, indent=2)
            except Exception as e:
                self.logger.warning("Could not write overhead JSON: %s", e)

            # 2. Anti-spoofing: physical DPID must match the claimed DID
            try:
                claimed_id = int(did.split(':')[2].split('_')[1])
                if dpid != claimed_id:
                    print(f"\n{C.RED}{C.B}  🚨 SPOOFING DETECTED {C.R}{C.GRY}│{C.R} dpid={C.MAG}s{dpid}{C.R} ≠ DID={C.YLW}{did}{C.R}\n")
                    return
            except Exception as e:
                self.logger.error("Invalid DID format: %s", e)
                return

            # 3. Switch approved
            is_reauth = dpid in self.authenticated_dpid
            self.authenticated_dpid.add(dpid)
            self.dpid_to_did[dpid] = did
            self.auth_expiry[dpid] = time.time() + AUTH_LIFETIME
            self.last_seen[dpid]   = time.time()
            self.reauth_pending.discard(dpid)   # Proactive re-auth complete
            self.did_documents[dpid] = self.ledger.resolve(did)  # Cache full DID Document

            expiry_str = time.strftime('%H:%M:%S',
                                       time.localtime(self.auth_expiry[dpid]))
            label = "🔄 RE-AUTH" if is_reauth else "✅ AUTH OK"
            print(f"\n{C.GRN}{C.B}  {label} {C.R}"
                  f"{C.GRY}│{C.R} {C.MAG}{C.B}s{dpid}{C.R} "
                  f"{C.GRY}│{C.R} {C.YLW}{did}{C.R} "
                  f"{C.GRY}│ expires at {expiry_str}{C.R} "
                  f"{C.GRY}│ ECDSA overhead:{C.R} {C.CYN}{t_ecdsa_ms:.2f} ms{C.R}\n")

            # 4. Recalculate routes now that this switch is trusted
            self._recalculate_all_paths()
            self._write_status()

        except Exception as e:
            self.logger.error("Error reading auth packet: %s", e)

    # =========================================================================
    # TOPOLOGY DISCOVERY (LLDP - via ryu.topology.switches)
    # =========================================================================

    @set_ev_cls(topo_event.EventSwitchEnter)
    def switch_enter_handler(self, ev):
        dpid = ev.switch.dp.id
        self.net.add_node(dpid)
        self.logger.info("TOPO: Switch s%s added to graph.", dpid)
        self._write_status()

    @set_ev_cls(topo_event.EventSwitchLeave)
    def switch_leave_handler(self, ev):
        dpid = ev.switch.dp.id
        print(f"\n{C.RED}{C.B}  ⚠️  QUARANTINE {C.R}{C.GRY}│{C.R} {C.MAG}{C.B}s{dpid}{C.R} {C.GRY}│{C.R} {C.RED}Switch lost — recalculating routes...{C.R}\n")

        # 1. Remove switch from topology graph
        if self.net.has_node(dpid):
            self.net.remove_node(dpid)

        # 2. Remove from datapath registry
        self.datapaths.pop(dpid, None)

        # 3. Remove from DID whitelist + clear time-related data
        self.authenticated_dpid.discard(dpid)
        self.dpid_to_did.pop(dpid, None)
        self.auth_expiry.pop(dpid, None)
        self.last_seen.pop(dpid, None)
        self.did_documents.pop(dpid, None)

        # 4. Forget hosts connected to this switch
        self.hosts = {
            mac: (sw, port)
            for mac, (sw, port) in self.hosts.items()
            if sw != dpid
        }

        # 5. Purge all routing rules on remaining switches
        self._delete_routing_flows()

        # 6. Recalculate routes avoiding the lost switch
        self._recalculate_all_paths()
        self.logger.info("TOPO: Recalculation done. Active switches: %s",
                         [f"s{d}" for d in self.authenticated_dpid])
        self._write_status()

    @set_ev_cls(topo_event.EventLinkAdd)
    def link_add_handler(self, ev):
        src = ev.link.src
        dst = ev.link.dst
        # Store the output port in the graph edge
        self.net.add_edge(src.dpid, dst.dpid, port=src.port_no)
        self.net.add_edge(dst.dpid, src.dpid, port=dst.port_no)
        self.logger.info("TOPO: Link added s%s <-> s%s", src.dpid, dst.dpid)
        self._recalculate_all_paths()
        self._write_status()

    @set_ev_cls(topo_event.EventLinkDelete)
    def link_delete_handler(self, ev):
        src = ev.link.src
        dst = ev.link.dst
        if self.net.has_edge(src.dpid, dst.dpid):
            self.net.remove_edge(src.dpid, dst.dpid)
        if self.net.has_edge(dst.dpid, src.dpid):
            self.net.remove_edge(dst.dpid, src.dpid)
        self.logger.info("TOPO: Link removed s%s <-> s%s", src.dpid, dst.dpid)
        self._delete_routing_flows()
        self._recalculate_all_paths()

    # =========================================================================
    # ROUTE COMPUTATION (DIJKSTRA / NetworkX)
    # =========================================================================

    def _get_path(self, src_dpid, dst_dpid):
        """Returns the Dijkstra path only through authenticated switches.
        In case of equal length, the lexicographically smallest path is
        always chosen to guarantee a deterministic result."""
        if src_dpid == dst_dpid:
            return [src_dpid]
        try:
            subgraph = self.net.subgraph(self.authenticated_dpid)
            paths = list(nx.all_shortest_paths(subgraph, src_dpid, dst_dpid))
            return min(paths)  # deterministic tie-break by DPID order
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            return None

    def _recalculate_all_paths(self):
        """Recomputes and installs routes for all known host pairs."""
        if len(self.hosts) < 2:
            return
        self.logger.info("=== Recomputing routes for %d known hosts ===",
                         len(self.hosts))
        macs = list(self.hosts.keys())
        for i, src_mac in enumerate(macs):
            for dst_mac in macs[i + 1:]:
                self._install_path_bidirectional(src_mac, dst_mac)

    def _install_path_bidirectional(self, mac_a, mac_b):
        """Installs OpenFlow rules in both directions between two hosts."""
        dpid_a, port_a = self.hosts[mac_a]
        dpid_b, port_b = self.hosts[mac_b]

        # Direction A → B
        path_ab = self._get_path(dpid_a, dpid_b)
        if path_ab:
            self._install_path(path_ab, dst_mac=mac_b, dst_port=port_b)
            hops = f" {C.GRY}──▶{C.R} ".join(f"{C.MAG}s{d}{C.R}" for d in path_ab)
            print(f"  {C.CYN}🔀 ROUTE{C.R} {C.GRY}│{C.R} {hops}")
        else:
            self.logger.warning("No path available: %s -> %s (switch down?)",
                                mac_a, mac_b)

        # Direction B → A
        path_ba = self._get_path(dpid_b, dpid_a)
        if path_ba:
            self._install_path(path_ba, dst_mac=mac_a, dst_port=port_a)

    def _install_path(self, path, dst_mac, dst_port):
        """
        Installs OpenFlow rules on each switch along the path.
          - Intermediate switch: match(eth_dst) → output(port to next hop)
          - Last switch:         match(eth_dst) → output(port to host)
        Only authenticated switches receive rules.
        """
        for i, dpid in enumerate(path):
            # Skip unauthenticated switches (Zero Trust)
            if dpid not in self.authenticated_dpid:
                continue
            dp = self.datapaths.get(dpid)
            if dp is None:
                continue

            parser = dp.ofproto_parser
            match = parser.OFPMatch(eth_dst=dst_mac)

            if i == len(path) - 1:
                # Last switch: deliver to host
                out_port = dst_port
            else:
                next_dpid = path[i + 1]
                if not self.net.has_edge(dpid, next_dpid):
                    continue
                out_port = self.net[dpid][next_dpid]['port']

            actions = [parser.OFPActionOutput(out_port)]
            self._add_flow(dp, priority=2, match=match,
                           actions=actions, cookie=ROUTING_COOKIE,
                           idle_timeout=10)

    # =========================================================================
    # OPENFLOW RULE MANAGEMENT
    # =========================================================================

    def _add_flow(self, datapath, priority, match, actions, cookie=0, idle_timeout=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=inst,
            cookie=cookie,
            idle_timeout=idle_timeout,
        )
        datapath.send_msg(mod)

    def _delete_routing_flows(self):
        """
        Purges only routing rules (identified by ROUTING_COOKIE)
        on all remaining switches. The table-miss rule (cookie=0) is preserved.
        """
        for dpid, datapath in list(self.datapaths.items()):
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser
            mod = parser.OFPFlowMod(
                datapath=datapath,
                command=ofproto.OFPFC_DELETE,
                out_port=ofproto.OFPP_ANY,
                out_group=ofproto.OFPG_ANY,
                match=parser.OFPMatch(),
                cookie=ROUTING_COOKIE,
                cookie_mask=0xFFFFFFFFFFFFFFFF,
            )
            datapath.send_msg(mod)
        self.logger.info("Routing rules purged on %d switches.",
                         len(self.datapaths))

    # =========================================================================
    # PACKET IN (main entry point)
    # =========================================================================

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        # Ignore LLDP and IPv6 multicast (Ryu internal traffic)
        if eth.ethertype == ether_types.ETH_TYPE_LLDP or eth.ethertype == 34525:
            return

        # --- ZERO TRUST: unauthenticated switch ---
        if dpid not in self.authenticated_dpid:
            pkt_udp = pkt.get_protocol(udp.udp)
            if pkt_udp and pkt_udp.dst_port == AUTH_PORT:
                self._handle_auth_packet(dpid, msg)
            return  # DROP all other traffic

        # --- Authenticated switch: update last_seen + MAC learning + routing ---
        self.last_seen[dpid] = time.time()
        src_mac = eth.src
        dst_mac = eth.dst

        # Record the source host location
        if src_mac not in self.hosts:
            self.hosts[src_mac] = (dpid, in_port)
            self.logger.info("Host discovered: %s on s%s port %s",
                             src_mac, dpid, in_port)
            # Install routes to/from this new host
            for other_mac in list(self.hosts.keys()):
                if other_mac != src_mac:
                    self._install_path_bidirectional(src_mac, other_mac)

        # IP flow tracing
        pkt_ip = pkt.get_protocol(ipv4.ipv4)
        if pkt_ip:
            identity = self.dpid_to_did.get(dpid, "Unknown")
            print(
                f"  {C.CYN}{C.B}📡 FLOW{C.R}"
                f" {C.GRY}│{C.R} {C.MAG}{C.B}s{dpid:<3}{C.R}"
                f" {C.GRY}│{C.R} {C.YLW}{identity}{C.R}"
                f" {C.GRY}│{C.R} {C.GRN}{pkt_ip.src}{C.R}"
                f" {C.WHT}{C.B} ──▶ {C.R}"
                f"{C.BLU}{pkt_ip.dst}{C.R}"
            )
            self.flow_seq += 1
            self.recent_flows.append({
                't'   : round(time.time(), 2),
                'dpid': dpid,
                'did' : identity,
                'src' : pkt_ip.src,
                'dst' : pkt_ip.dst,
            })
            if len(self.recent_flows) > 60:
                self.recent_flows = self.recent_flows[-60:]
            self._write_status()

        # Forward current packet (while flow rules are being installed)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        if dst_mac not in self.hosts:
            # Unknown destination: DROP to avoid loops (no STP)
            return

        dst_dpid, dst_port_host = self.hosts[dst_mac]
        path = self._get_path(dpid, dst_dpid)
        if not path:
            # No path available (switch down?)
            return

        if len(path) > 1:
            out_port = self.net[path[0]][path[1]]['port']
        else:
            out_port = dst_port_host

        actions = [parser.OFPActionOutput(out_port)]
        data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data,
        )
        datapath.send_msg(out)

    # =========================================================================
    # EXPIRATION MONITORING (background thread)
    # =========================================================================

    def _expiry_monitor(self):
        """Ryu greenthread: periodically checks token expiry and inactivity."""
        hub.sleep(CHECK_INTERVAL)
        while True:
            self._check_expired_auths()
            self._write_status()   # Update token countdown
            hub.sleep(CHECK_INTERVAL)

    def _check_expired_auths(self):
        now = time.time()
        to_quarantine = []

        for dpid in list(self.authenticated_dpid):
            remaining = self.auth_expiry.get(dpid, 0) - now
            # 1. Token expired → quarantine
            if remaining <= 0:
                to_quarantine.append((dpid, 'expiration'))
            # 2. Switch inactive → quarantine
            elif now - self.last_seen.get(dpid, now) > INACTIVITY_TIMEOUT:
                to_quarantine.append((dpid, 'inactivity'))
            # 3. Token expiring soon → proactive re-auth (if not already in progress)
            elif remaining < REAUTH_THRESHOLD and dpid not in self.reauth_pending:
                self.reauth_pending.add(dpid)
                hub.spawn(self._trigger_reauth, dpid)

        for dpid, reason in to_quarantine:
            self._quarantine_expired(dpid, reason)

    def _quarantine_expired(self, dpid, reason):
        """Quarantines a switch whose token has expired or which is inactive."""
        did = self.dpid_to_did.get(dpid, f"unknown")

        if reason == 'expiration':
            print(f"\n{C.YLW}{C.B}  ⏰ TOKEN EXPIRED  {C.R}"
                  f"{C.GRY}│{C.R} {C.MAG}{C.B}s{dpid}{C.R} "
                  f"{C.GRY}│{C.R} {C.YLW}{did}{C.R} "
                  f"{C.GRY}→ automatic quarantine{C.R}\n")
        else:
            print(f"\n{C.BLU}{C.B}  💤 INACTIVITY    {C.R}"
                  f"{C.GRY}│{C.R} {C.MAG}{C.B}s{dpid}{C.R} "
                  f"{C.GRY}│{C.R} {C.YLW}{did}{C.R} "
                  f"{C.GRY}→ automatic quarantine{C.R}\n")

        # Remove from whitelist (node stays in self.net for quick reconnection)
        self.authenticated_dpid.discard(dpid)
        self.dpid_to_did.pop(dpid, None)
        self.auth_expiry.pop(dpid, None)
        self.last_seen.pop(dpid, None)
        self.did_documents.pop(dpid, None)

        # Forget hosts connected to this switch
        self.hosts = {
            mac: (sw, port)
            for mac, (sw, port) in self.hosts.items()
            if sw != dpid
        }

        # Purge routing rules and recompute without this switch
        self._delete_routing_flows()
        self._recalculate_all_paths()
        self.logger.info("EXPIRATION: s%s quarantined. Active switches: %s",
                         dpid, [f"s{d}" for d in self.authenticated_dpid])
        self._write_status()

    def _trigger_reauth(self, dpid):
        """Proactive re-auth: triggers agent_auth.py via nsenter from h{dpid}."""
        did = self.dpid_to_did.get(dpid, f'switch_{dpid}')
        print(f"\n{C.CYN}{C.B}  🔄 AUTO RE-AUTH  {C.R}"
              f"{C.GRY}│{C.R} {C.MAG}{C.B}s{dpid}{C.R} "
              f"{C.GRY}│{C.R} {C.CYN}{did}{C.R} "
              f"{C.GRY}→ token expires in < {REAUTH_THRESHOLD}s{C.R}\n")
        try:
            with open(PIDS_FILE) as f:
                pids = json.load(f)
            pid = pids.get(str(dpid))
            if not pid:
                self.logger.warning("REAUTH: PID not found for h%s", dpid)
                self.reauth_pending.discard(dpid)
                return
            r = subprocess.run(
                ['nsenter', '-n', '-t', str(pid), '--',
                 'python3', AGENT_PATH, f'switch_{dpid}'],
                capture_output=True, timeout=8
            )
            if r.returncode != 0:
                self.logger.warning("REAUTH: Failed for s%s: %s",
                                    dpid, r.stderr.decode().strip())
                self.reauth_pending.discard(dpid)
        except FileNotFoundError:
            self.logger.warning("REAUTH: %s not found — is Mininet running?", PIDS_FILE)
            self.reauth_pending.discard(dpid)
        except Exception as e:
            self.logger.error("REAUTH: Error for s%s: %s", dpid, e)
            self.reauth_pending.discard(dpid)

    # =========================================================================
    # JSON STATUS (shared with monitoring terminal)
    # =========================================================================

    def _write_status(self):
        """Writes the auth state of all switches to a JSON file."""
        now    = time.time()
        status = {}
        for dpid in range(1, NUM_SWITCHES + 1):
            if dpid in self.authenticated_dpid:
                status[str(dpid)] = {
                    'state'    : 'auth',
                    'did'      : self.dpid_to_did.get(dpid, ''),
                    'expiry'   : self.auth_expiry.get(dpid, 0),
                    'last_seen': self.last_seen.get(dpid, 0),
                }
            elif dpid in self.datapaths:
                status[str(dpid)] = {'state': 'connected'}
            else:
                status[str(dpid)] = {'state': 'unknown'}
        # Topology: deduplicated edges for the web dashboard
        seen_pairs = set()
        edges = []
        for src, dst in self.net.edges():
            pair = (min(src, dst), max(src, dst))
            if pair not in seen_pairs:
                seen_pairs.add(pair)
                edges.append([src, dst])
        status['_edges'] = edges
        status['_flows']    = self.recent_flows[-40:]
        status['_flow_seq'] = self.flow_seq

        try:
            with open(STATUS_FILE, 'w') as f:
                json.dump(status, f)
        except IOError:
            pass
