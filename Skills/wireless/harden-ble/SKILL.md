---
name: harden-ble
description: "GATT access control and pairing hardening for Bluetooth Low Energy devices that treat the radio link as the trust boundary: privileged GATT characteristics left open without authentication or encryption, Just Works pairing with no MITM protection, and LE Legacy Pairing with a recoverable key (MITRE ATT&CK T1557, T1040, T1011.001). The signal is link and attribute layer: HCI and btsnoop traces, the SMP pairing exchange, ATT error responses, BlueZ bluetoothd journald records, and Windows Bluetooth ETW channels. The skill gives the GATT permission model to enforce, the pairing settings to mandate (LE Secure Connections, 16-byte keys), defender-view signals, a hunt, and framework-mapped hardening. Use when designing or reviewing a BLE GATT server, hardening pairing on an IoT device, smart lock, or BLE gateway, triaging an unbonded peer that walked your GATT tree, or hunting for Just Works and LE Legacy Pairing downgrades."
---

# Bluetooth Low Energy (GATT / Pairing) - Defensive Methodology

> **Tier 2 - methodology skill.** No bespoke UMBRASEC detection rule ships with this skill yet. It gives the defender's method, the log sources and signals, and the hardening, and points to public rule and reference sources. Promotion to Tier 1 (a sourced, tuned UMBRASEC rule) is tracked in [COVERAGE.md](https://github.com/umbrasec-labs/umbra-blue/blob/main/COVERAGE.md). Do not treat the content below as citing a UMBRASEC rule; there is none for this threat yet.

## TL;DR

Most BLE weaknesses are design defects, not patchable bugs. Two fixes close the bulk of them. First, **GATT access control**: every characteristic that reads sensitive data or drives the device must carry a permission requiring an encrypted and authenticated link (and, for the highest-value operations, application-layer authorization), not the default of open read/write. Second, **pairing hardening**: mandate **LE Secure Connections** (ECDH P-256, Core Spec 4.2 and later), reject **LE Legacy Pairing**, forbid **Just Works** for anything privileged by requiring MITM protection (passkey entry or numeric comparison), and set the minimum encryption key size to 16 bytes so a downgrade cannot shrink it. The telemetry that shows whether this holds is link-layer, not host-layer: an HCI or btsnoop capture of the SMP exchange and the ATT traffic. This skill is defensive and ships no BLE enumeration, pairing-downgrade, relay, or sniffing tooling.

## What it looks like, defender view

An unbonded peer connects and walks the GATT tree, then issues ATT Read and Write requests against privileged handles. On a hardened server you see a burst of **ATT Error Responses** (ATT opcode `0x01`) carrying `Insufficient Authentication` (`0x05`), `Insufficient Encryption` (`0x0F`), `Insufficient Authorization` (`0x08`), or `Insufficient Encryption Key Size` (`0x0C`) across many handles from one peer in seconds. On a weak server you see the opposite and worse: successful Read or Write responses to control characteristics while the link is still unencrypted, because the characteristic carried no permission requirement at all.

In the pairing exchange, the downgrade tells are explicit in the SMP **Pairing Request / Response** (`0x01` / `0x02`): an **IO Capability** of `NoInputNoOutput` on either side forces **Just Works**; the **AuthReq** byte with the **MITM bit (bit 2) clear** means no man-in-the-middle protection was requested, and the **Secure Connections bit (bit 3) clear** means LE Legacy Pairing. Repeated **Pairing Failed** (`0x05`) with reason `Authentication Requirements` (`0x03`) followed by a retry at weaker settings is downgrade probing. A relay or active MITM shows as two near-simultaneous connections to the same logical device with abnormal round-trip latency.

## Log sources and signals

The signal is at the link (HCI / SMP) and attribute (ATT) layer. BLE link-layer PDUs are not log records, so this is a poor fit for log-oriented rule engines; capture and analysis tooling is the right instrument. Use one or more of:

- **HCI / btsnoop traces.** `btmon` and `hcidump` on Linux, and btsnoop logs (BlueZ via `btmon -w <file>`, Android HCI snoop `btsnoop_hci.log`), opened in Wireshark with display filters `btsmp`, `btatt`, and `btl2cap`.
  - **SMP fields:** Pairing Request/Response IO Capability, OOB Data flag, AuthReq (bonding bits 0-1, MITM bit 2, SC bit 3), and **Max Encryption Key Size**. Pairing Failed reason codes (`0x03` Authentication Requirements, `0x04` Confirm Value Failed, `0x05` Pairing Not Supported).
  - **HCI events:** `LE Connection Complete`, `Encryption Change` (event `0x08`), and `LE Long Term Key Request` - the ATT privileged operation should never succeed before the Encryption Change.
  - **ATT opcodes:** Read Request (`0x0A`), Write Request (`0x12`), Write Command (`0x52`), and the Error Response (`0x01`) with the insufficient-* codes above.
- **BlueZ host.** `bluetoothd` via journald (`journalctl -u bluetooth`), the D-Bus `Device1` pairing and bonding signals, and the stored bond file `/var/lib/bluetooth/<adapter>/<device>/info`, whose key blocks and authentication flags reveal whether a bond used LE Secure Connections and at what key size.
- **Windows.** Bluetooth ETW providers `Microsoft-Windows-Bluetooth-BthLEEnum`, `Microsoft-Windows-Bluetooth-BthPort`, and `Microsoft-Windows-Bluetooth-Bthmini`, plus device-pairing records surfaced through `Microsoft-Windows-DeviceSetupManager`.
- **Device / gateway and companion app.** The GATT server's own per-connection state (peer address, bond status, encryption state, negotiated key size) and bond-establishment logs on the gateway or companion app.

**Baseline.** Known bonded peers reconnect using an existing LTK, so the link is encrypted before any privileged ATT operation and the steady-state count of insufficient-authentication ATT errors is near zero. Pairing, when it happens, uses LE Secure Connections with MITM protection and a 16-byte key.

## Detection approach

Alert on access-control and pairing anomalies, not on single packets. The high-signal conditions are: (1) a spike of ATT Error Responses with `Insufficient Authentication` / `Insufficient Encryption` / `Insufficient Authorization` / `Insufficient Encryption Key Size` across many distinct handles from one peer in a short window, which is characteristic enumeration against a server that is at least enforcing permissions; (2) any **successful** ATT Read or Write to a privileged characteristic while the link is unencrypted (no prior Encryption Change), which means a characteristic is missing its permission requirement; (3) an SMP exchange that negotiates **Just Works** (either IO capability `NoInputNoOutput`, neither side setting the MITM bit, or another IO-capability pair that the mapping table resolves to Just Works) or **LE Legacy Pairing** (SC bit clear) for a device your policy says must use LE Secure Connections with MITM; and (4) repeated Pairing Failed `0x03` then a retry at weaker parameters, i.e. downgrade probing.

Because the evidence is link-layer, a tuned UMBRASEC rule is not yet shipped for this threat, and conditions (1) to (4) are expressed against capture tooling rather than a SIEM log schema. For the host-side events that *are* log-shaped (BlueZ journald records, Windows Bluetooth ETW channels, device-install events), track SIEM detections in the general [SigmaHQ repository](https://github.com/SigmaHQ/sigma). For the protocol-level analysis use the [Wireshark Bluetooth protocol filters](https://www.wireshark.org/docs/dfref/b/btatt.html) (`btatt`, `btsmp`), the [Bluetooth Core Specification](https://www.bluetooth.com/specifications/specs/core-specification/) SMP and Security Manager sections, and [NIST SP 800-121 Rev. 2, Guide to Bluetooth Security](https://csrc.nist.gov/pubs/sp/800/121/r2/upd1/final).

## Threat hunt

Hypothesis: a privileged characteristic is reachable without an authenticated, encrypted link, or a device pairs below policy.

1. **Audit the GATT permission model.** Enumerate the server's declared characteristics and their permission flags. Any characteristic that reads sensitive data or changes device state and is declared with no permission, or with read/write permitted on an unencrypted link, is a finding regardless of whether an attack has occurred.
2. **Capture a real pairing.** Record one bonding with `btmon` and confirm in the SMP exchange that the SC bit is set (LE Secure Connections), MITM protection was used (passkey entry or numeric comparison, not Just Works), and Max Encryption Key Size is 16. Anything less is a downgrade the device accepts.
3. **Look for ATT before encryption.** In a btsnoop capture, find ATT Write Request / Command or Read Request to control or data handles that occur before the `Encryption Change` event on that connection.
4. **Review stored bonds.** On BlueZ hosts and gateways, inspect `/var/lib/bluetooth/<adapter>/<device>/info` for bonds established under LE Legacy Pairing or with a key size below 16, and remove stale or weak bonds.

## Hardening

Shrink the surface by fixing the design, then detection is a backstop rather than the primary control. The mappings below follow the control codes used in the UMBRASEC [identity and access guide](https://umbrasec.dev/guide/identity-and-access.html); a cell is left blank where no single control maps cleanly (the cryptographic strength of LE Secure Connections, for example, is a protocol property rather than a governance control, and the Essential Eight is a Windows-estate model that does not address BLE radio design).

| Control | What it does | Essential Eight | ISO 27001:2022 | NIST CSF 2.0 |
|---|---|---|---|---|
| GATT characteristic access control | Require an encrypted and authenticated link (and app-layer authorization for the highest-value operations) on every privileged characteristic; default-deny, least privilege per characteristic | - | A.5.15 Access control; A.8.2 Privileged access rights | PR.AA-05 Least privilege |
| Mandate LE Secure Connections | Reject LE Legacy Pairing so the key exchange is ECDH P-256, not a recoverable legacy short-term key | - | A.8.5 Secure authentication | PR.AA-03 |
| Require authenticated pairing (MITM protection) | Forbid Just Works for privileged use; require passkey entry or numeric comparison so an active man-in-the-middle is detected at pairing | - | A.5.17 Authentication information; A.8.5 Secure authentication | PR.AA-01 |
| Enforce 16-byte encryption key size | Reject key-size downgrade negotiation that would weaken the link encryption | - | A.8.5 Secure authentication | - |
| Bond lifecycle management | Store only LE Secure Connections bonds, review and remove stale or weak bonds, re-pair after a factory reset | - | A.5.18 Access rights | PR.AA-05 Least privilege |

## Honest limitations

The link-layer signal needs a sniffer or an instrumented stack you often do not have on a shipped IoT device, so on fielded hardware the audit (hunt steps 1 and 4) usually matters more than live detection. Enforcing permissions removes the detection opportunity for the unauthenticated-read case entirely: once a characteristic requires encryption, the earlier benign-looking open reads simply stop, which is the point, but it means the fix is design, not monitoring. Passive sniffing of an already-established LE Secure Connections session yields nothing, which is the goal, yet the same encryption blinds a passive defender to a legitimately paired but malicious peer. Finally, pairing hardening does not stop a **relay / proximity** attack against a correctly paired LE Secure Connections device (the class used against some cars and smart locks): the relay forwards a genuine authenticated exchange across distance, and defeating it needs distance or time bounding such as BLE Channel Sounding, which most devices do not yet implement. Name that gap rather than imply pairing hardening closes it.

## ATT&CK and D3FEND

- MITRE ATT&CK: [T1557 Adversary-in-the-Middle](https://attack.mitre.org/techniques/T1557/) (Credential Access, Collection) for the Just Works / LE Legacy downgrade and relay MITM; [T1040 Network Sniffing](https://attack.mitre.org/techniques/T1040/) (Credential Access, Discovery) for BLE sniffing of weakly paired links; [T1011.001 Exfiltration Over Bluetooth](https://attack.mitre.org/techniques/T1011/001/) (Exfiltration) for data pulled over the BLE medium.
- MITRE D3FEND: [D3-MENCR Message Encryption](https://d3fend.mitre.org/technique/d3f:MessageEncryption/) and [D3-MAN Message Authentication](https://d3fend.mitre.org/technique/d3f:MessageAuthentication/), which together describe enforcing an authenticated, encrypted link (LE Secure Connections) and so counter the AiTM case; [D3-NTA Network Traffic Analysis](https://d3fend.mitre.org/technique/d3f:NetworkTrafficAnalysis/) for the capture-side detection.
- Public rule and reference sources: [NIST SP 800-121 Rev. 2, Guide to Bluetooth Security](https://csrc.nist.gov/pubs/sp/800/121/r2/upd1/final); [Bluetooth Core Specification](https://www.bluetooth.com/specifications/specs/core-specification/) (Security Manager / SMP, LE Secure Connections); [Wireshark Bluetooth ATT](https://www.wireshark.org/docs/dfref/b/btatt.html) and SMP protocol filters; [SigmaHQ repository](https://github.com/SigmaHQ/sigma) for host-side BlueZ and Windows Bluetooth device-event rules.

**Scope note.** This is a defensive skill. It explains BLE GATT and pairing only to the depth needed to harden a device and detect abuse, and deliberately ships no GATT enumeration, pairing-downgrade, relay, or sniffing tooling. UMBRASEC publishes defense, not offense.
