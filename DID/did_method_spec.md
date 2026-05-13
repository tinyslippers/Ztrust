# did:depin DID Method Specification

**Method name:** `depin`  
**Status:** Research prototype — not submitted to W3C DID Method Registry  
**Version:** 1.0  
**Authors:** Baptiste Rodrigues — ESME INGE3

---

## Abstract

The `did:depin` DID Method defines how Decentralized Identifiers are created, resolved, updated, and revoked for network infrastructure nodes (switches) in a Software-Defined Networking environment. It follows the [W3C Decentralized Identifiers (DIDs) v1.0](https://www.w3.org/TR/did-core/) specification. Each switch holds an ECDSA secp256k1 key pair; its public key and metadata are stored as a W3C DID Document in a local append-only blockchain ledger.

---

## 1. DID Method Name

The method name is `depin` (Decentralized Physical Infrastructure Network).

---

## 2. DID Syntax

A `did:depin` DID has the following structure:

```
did:depin:<node-id>

node-id = 1*( ALPHA / DIGIT / "_" / "-" )
```

**Examples:**

```
did:depin:switch_1
did:depin:switch_22
```

The `node-id` is a human-readable, stable identifier assigned at provisioning time. It maps directly to the physical switch name in the Mininet/OVS topology, enabling the controller to cross-check the DID claim against the physical DPID (anti-spoofing).

---

## 3. DID Document Structure

A resolved `did:depin` DID Document conforms to the W3C DID Core data model:

```json
{
  "@context": "https://www.w3.org/ns/did/v1",
  "id": "did:depin:switch_1",
  "verificationMethod": [{
    "id": "did:depin:switch_1#keys-1",
    "type": "EcdsaSecp256k1VerificationKey2019",
    "controller": "did:depin:switch_1",
    "publicKeyHex": "<64-byte secp256k1 public key hex>"
  }],
  "authentication": ["did:depin:switch_1#keys-1"],
  "service": [{
    "id": "did:depin:switch_1#sdn",
    "type": "SDNEndpoint",
    "serviceEndpoint": "udp://controller:9999"
  }],
  "flow_policy": {
    "allowed_flows": [],
    "default": "deny"
  }
}
```

**Standard W3C fields:**

| Field | Description |
|---|---|
| `@context` | W3C DID context URI |
| `id` | The DID itself |
| `verificationMethod` | ECDSA secp256k1 public key (EcdsaSecp256k1VerificationKey2019) |
| `authentication` | Reference to the verification method used for switch authentication |
| `service` | SDN controller endpoint (UDP port 9999) |

**Extension field (`flow_policy`):** a ZTrust-specific extension that defines allowed traffic flows and the default action. Not part of the W3C core spec but permitted as an extension property.

---

## 4. CRUD Operations

### 4.1 Create

A DID Document is created by calling `Blockchain.add_identity()`. This appends a new block to the ledger containing the full DID Document.

```python
blockchain.add_identity("did:depin:switch_1", public_key_hex)
```

The DID is considered registered once the block is appended and `save_chain()` writes the ledger to disk. There is no mining delay (research prototype).

**Key generation** (performed offline by `gen_did.py`):

```bash
cd DID
python3 gen_did.py
# Generates keystore/secrets.json (private keys) + ledger.json (DID Documents)
```

### 4.2 Read / Resolve

DID resolution is performed by `Blockchain.resolve(did)`, which scans the chain from the latest block backwards and returns the first non-revoked DID Document matching the requested DID:

```python
did_doc = blockchain.resolve("did:depin:switch_1")
# Returns: dict (DID Document) or None if not found / revoked
```

Resolution semantics:
- If the most recent block for this DID contains `"revoked": True` → returns `None`
- Otherwise → returns the most recent DID Document (latest-block-wins)
- If no block matches → returns `None`

The SDN controller calls `resolve()` during switch authentication in `verify_signature()`. The full DID Document is cached in `did_documents[dpid]` after successful auth for use by future policy enforcement.

### 4.3 Update

To rotate a key or update the DID Document, append a new block with the same `id` using `add_identity()`. The latest block always supersedes previous ones during resolution.

```python
blockchain.add_identity("did:depin:switch_1", new_public_key_hex)
```

### 4.4 Delete / Revoke

Revocation is performed by appending a revocation block. After revocation, `resolve()` returns `None` and the switch will fail authentication.

```python
blockchain.revoke_identity("did:depin:switch_1")
```

Revocation is permanent in this implementation (no unrevoke). Re-registration after revocation requires a new `add_identity()` call.

---

## 5. Security Considerations

### 5.1 Key Security

Private keys are generated offline by `gen_did.py` and stored in `keystore/secrets.json`, which is excluded from version control (`.gitignore`). Private keys never appear in the blockchain ledger or in any network packet. Authentication packets contain only a signature over a timestamped challenge.

### 5.2 Blockchain Integrity

The ledger is a SHA-256 chained structure. `Blockchain.is_valid()` verifies both the hash of each block's contents and the chain linkage (`previous_hash`). This check runs at controller startup — a tampered ledger raises `ValueError` and the controller refuses to start.

### 5.3 Anti-Replay

Auth packets include a Unix timestamp. The controller rejects packets where `abs(now − timestamp) > 30 seconds`, preventing replay of captured auth packets.

### 5.4 Anti-Spoofing

The physical DPID of the incoming OpenFlow connection is compared to the numeric ID embedded in the DID string (`switch_N` → `N`). A mismatch triggers an immediate drop with a `SPOOFING DETECTED` warning.

### 5.5 Revocation Timeliness

Revocation takes effect immediately at the ledger level. However, a switch that is already authenticated holds a valid token for up to 30 minutes (`AUTH_LIFETIME`). For immediate forced quarantine, use the dashboard or call `_quarantine_expired()` directly.

### 5.6 Known Limitations

- **Single-node ledger** — the blockchain is a local file. No distributed consensus. A host with write access to `ledger.json` could replace the entire file. For production, replace with Hyperledger Fabric or an Ethereum-based registry.
- **No TLS on OpenFlow** — the controller-to-switch channel (TCP 6633) is unencrypted. A MitM on the management plane could inject flow rules.
- **No DID Document signing** — DID Documents in the ledger are not themselves signed by a trusted authority. The integrity guarantee comes from the hash chain, not from a root of trust.

---

## 6. Privacy Considerations

- The ledger contains only public keys and network metadata (switch names, service endpoints). No personally identifiable information (PII) is stored.
- Switch names (`switch_1` … `switch_22`) are infrastructure identifiers, not human identities.
- The ledger (`ledger.json`) is safe to publish and is committed to the repository.
- Private keys are never stored in the ledger or transmitted over the network.

---

## 7. Reference Implementation

| Component | File |
|---|---|
| DID Document storage & resolution | `DID/blockchain.py` |
| Controller-side verification | `DID/did_controller.py` — `verify_signature()` |
| Key generation & DID provisioning | `DID/gen_did.py` |
| Authentication agent (runs on switch) | `DID/agent_auth.py` |
| Attack validation suite | `DID/attack_simulation.py` |

**Repository:** `did-w3c-compliant` branch of the ZTrust project.
