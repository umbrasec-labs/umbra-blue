---
name: harden-lorawan-sub-ghz
description: "Harden the LoRaWAN join procedure and session keys against capture, replay, and injection on sub-GHz (433/868/915 MHz) IoT networks, where an attacker sniffs OTAA joins, replays Join-Requests or uplinks, abuses weak frame-counter and DevNonce handling to force session-key reuse, and injects downlinks (MITRE ATT&CK T1040, T1557; ICS T0887, T0860, T0830). Signal lives in network-server and join-server telemetry: ChirpStack, The Things Stack, AWS IoT Core for LoRaWAN, and Actility ThingPark, plus gateway RSSI/SNR metadata. Gives detectable indicators (DevNonce reuse, MIC failures, frame-counter resets, join floods), a hypothesis-driven hunt, and a join/session-key hardening plan mapped to ISO 27001 and NIST CSF. Use when hardening a LoRaWAN deployment, hunting LoRaWAN replay or join-flood activity, triaging MIC-failure or frame-counter alerts, or reviewing OTAA versus ABP key provisioning."
---

# LoRaWAN Join and Session-Key Attacks - Defensive Methodology

> **Tier 2 - methodology skill.** No bespoke UMBRASEC detection rule ships with this skill yet. It gives the defender's method, the log sources and signals, the hunt, and the join/session-key hardening, and it points to public rule and standards sources. Promotion to Tier 1 (a sourced, tuned UMBRASEC rule) is tracked in [COVERAGE.md](https://github.com/umbrasec-labs/umbra-blue/blob/main/COVERAGE.md). Do not treat the content below as citing a UMBRASEC rule; there is none for this threat yet.

## TL;DR

LoRaWAN security rests entirely on the integrity of the join procedure and the session keys it derives. An attacker on the RF channel cannot break AES-128, but can capture the OTAA Join-Request and Join-Accept, replay old frames, and abuse weak DevNonce or frame-counter handling to force key reuse or process stale traffic as fresh. You rarely see the radio; you see the network server rejecting or mishandling frames. Watch your network-server and join-server logs for four things: a Join-Request that reuses a DevNonce, a spike in MIC (Message Integrity Code) failures, an uplink or downlink frame counter that resets or repeats, and a device that floods join requests. Prefer OTAA over ABP, enforce unique per-device root keys, upgrade to LoRaWAN 1.1 so DevNonce is a tracked counter, and ship the server event streams to your SIEM. No single signal is conclusive on a noisy multi-gateway network; layer them.

## What it looks like, defender view

Over the air the attack is a captured and replayed packet, so there is almost nothing to see at the radio. The evidence surfaces at the network server, which is the single component that holds the keys and enforces anti-replay. A replayed OTAA Join-Request arrives with a DevNonce the server has already seen for that DevEUI; a LoRaWAN 1.1 server must reject it, a 1.0.x server using random DevNonce may accept it and derive a fresh session, which is itself the abuse. A forged or injected frame arrives with a MIC the server cannot verify, producing a MIC-failure event. A replayed uplink carries a frame counter (FCnt) equal to or below the last value the server accepted, so it appears as a retransmission or a counter reset. A device being hammered to renegotiate keys or drain its battery shows as a burst of Join-Requests from one DevEUI. None of this requires the attacker to have broken crypto; it requires only RF capture and a permissive server configuration.

## Log sources and signals

The telemetry is the network server and join server, not the gateway radio. Ship these to your SIEM.

- **ChirpStack** emits structured device events and an error stream (over its MQTT integration and logs). Relevant event and error types include join events, uplink events, and errors such as uplink MIC failures, frame-counter retransmission, and frame-counter reset/rollback. Key fields: `devEUI`, `joinEUI`/`appEUI`, `devAddr`, `fCnt`, `dr` (data rate), `rssi`, `snr`, `gatewayID`.
- **The Things Stack (v3)** exposes an event stream. Relevant events include network-server join receive/accept, MAC-layer events, and uplink/downlink processing errors (bad MIC, frame-counter too low, duplicate). Fields mirror the above: `dev_eui`, `join_eui`, `dev_addr`, `f_cnt`, `rssi`, `snr`, `gateway_ids`.
- **AWS IoT Core for LoRaWAN** and **Actility ThingPark** publish equivalent connection, join, and uplink/downlink logs with the same LoRaWAN identifiers.
- **Gateway metadata** (RSSI, SNR, gateway_id, timestamp) rides on every uplink. It is context, not an alarm: a device whose frames suddenly arrive via an unexpected gateway or at an implausible RSSI is worth a look.

What normal looks like, so the anomaly is legible: a healthy OTAA device joins rarely (at power-on or after session loss), then sends uplinks with a strictly monotonic FCntUp. Duplicate uplinks arriving via several gateways within the de-duplication window are normal and are collapsed by the server. MIC failures should be near zero in steady state. A DevNonce should never repeat for a given DevEUI on a 1.1 network.

## Detection approach

Alert on the server-side integrity failures, because those are where replay and injection become visible and where false positives are lowest.

1. **DevNonce reuse.** On LoRaWAN 1.1 the join server tracks DevNonce as a monotonic counter and rejects a non-incrementing value; make that rejection an alert, not a silent drop. On 1.0.0 to 1.0.3 (random DevNonce) a repeated DevNonce for the same DevEUI within the server's retention window is the equivalent signal.
2. **MIC-failure spike.** A sustained rise in uplink or join MIC failures for a device, or across a gateway, indicates forged/injected frames or a key mismatch. Baseline the near-zero steady state and alert on deviation.
3. **Frame-counter anomaly.** FCntUp that resets to a lower value, repeats, or jumps implausibly is the uplink-replay and session-reuse signal. Treat a counter reset on an OTAA device that did not re-join as high interest.
4. **Join flood.** Repeated Join-Requests from one DevEUI in a short window suggest an attacker forcing session renegotiation or battery drain.

There is no widely maintained public Sigma ruleset dedicated to LoRaWAN network-server events today, so this skill does not point you at one that does not exist. The practical path is to normalize the ChirpStack or The Things Stack event/error stream into your SIEM and author the four correlations above against those fields. Use the public SigmaHQ repository ([github.com/SigmaHQ/sigma](https://github.com/SigmaHQ/sigma)) as the format and category reference, the ChirpStack event documentation ([chirpstack.io](https://www.chirpstack.io/)) and The Things Stack events documentation ([thethingsindustries.com/docs](https://www.thethingsindustries.com/docs/)) for the exact event and error identifiers your deployment emits, and MITRE D3FEND ([d3fend.mitre.org](https://d3fend.mitre.org/)) for the countermeasure framing. A tuned UMBRASEC rule for this threat is not yet shipped; see the Tier 2 banner above.

## Threat hunt

Hypothesis: an attacker is replaying captured frames or forcing session-key renegotiation against one or more devices.

1. Pull every join event for the hunt window and group by `devEUI`. Flag any DevEUI with more than a handful of joins, and any DevEUI whose DevNonce values are not strictly increasing (1.1) or repeat (1.0.x).
2. Pull MIC-failure errors and group by `devEUI` and `gatewayID`. A device or gateway with a non-trivial MIC-failure count against a near-zero baseline is a candidate for injection or key mismatch.
3. Pull uplinks for each flagged device, order by server receive time, and inspect `fCnt`: look for resets to a lower value, repeats, or an OTAA device whose counter reset without a corresponding join.
4. Correlate gateway metadata: for a flagged device, did frames begin arriving via a new `gatewayID` or at a markedly different RSSI/SNR around the same time? That strengthens the relay/replay hypothesis without proving it.
5. Rank by blast radius: a device that actuates or carries industrial/safety telemetry outranks a benign sensor, because a successful downlink injection there has physical consequences.

## Hardening

Shrink the join and session-key attack surface. Mappings below use control codes grounded in the UMBRASEC [governance and maturity guide](https://umbrasec.dev/guide/governance-and-maturity.html) and [identity and access guide](https://umbrasec.dev/guide/identity-and-access.html); a cell is left blank where no single control maps cleanly. The ASD Essential Eight is Windows-estate oriented and maps poorly to LoRaWAN, so most of its column is blank by design, which is honest rather than a gap.

| Control | What it does | Essential Eight | ISO 27001:2022 | NIST CSF 2.0 |
|---|---|---|---|---|
| Prefer OTAA over ABP | Derives fresh session keys per join with mutual authentication, instead of static pre-flashed keys that never rotate | - | A.8.5 Secure authentication | PR.AA |
| Unique per-device root keys | Eliminates the shared-AppKey/NwkKey failure where one extracted key compromises a whole fleet | - | A.5.17 Authentication information | PR.AA-01 |
| Upgrade to LoRaWAN 1.0.4 or 1.1 | Makes DevNonce a tracked monotonic counter (both versions) and, in 1.1, adds join-server separation, closing the random-DevNonce replay path | Patch operating systems (firmware) | A.8.8 Technical vulnerabilities | PR.PS |
| Enforce 32-bit frame counters and reject resets | Prevents stale uplinks being accepted as fresh and prevents counter-rollover replay | - | - | PR.DS |
| Provision keys in a secure element or join server | Keeps root keys out of extractable firmware, so capture alone does not yield session keys | - | A.5.17 Authentication information | PR.AA-01 |
| Network-server logging and MIC/FCnt monitoring | Turns the integrity failures above into alerts rather than silent drops | - | A.8.15 Logging; A.8.16 Monitoring | DE.CM; DE.AE |
| Device and key inventory | Knows every DevEUI and which key set it carries, so an unknown joiner or a shared key is visible | - | A.5.9 Inventory of assets | ID.AM |

## Honest limitations

This method watches the network server, so it cannot see an attacker who only passively captures and never injects or replays; capture alone leaves no server-side trace, and the defense against it is encryption and non-extractable keys, not detection. On ABP devices with no frame-counter enforcement, a single well-timed replay may blend into normal retransmissions. DevNonce and frame-counter signals depend on the server retaining enough state; a server that forgets DevNonce history or resets counters on restart creates blind spots. MIC failures also rise for benign reasons (a desynchronized key set, a flapping device, a misconfigured gateway), so a spike warrants investigation, not an automated block. On a dense multi-gateway network, duplicate frames and legitimate retransmissions add noise that you must baseline before alerting. Treat every signal as evidence to weigh, baseline in report-only mode first, and leave the final call to the defender.

## ATT&CK and D3FEND

- MITRE ATT&CK (Enterprise): [T1040 Network Sniffing](https://attack.mitre.org/techniques/T1040/), [T1557 Adversary-in-the-Middle](https://attack.mitre.org/techniques/T1557/).
- MITRE ATT&CK (ICS): [T0887 Wireless Sniffing](https://attack.mitre.org/techniques/T0887/), [T0860 Wireless Compromise](https://attack.mitre.org/techniques/T0860/), [T0830 Adversary-in-the-Middle](https://attack.mitre.org/techniques/T0830/).
- MITRE D3FEND: [D3-MAN Message Authentication](https://d3fend.mitre.org/technique/d3f:MessageAuthentication/) (verifies frame MIC to defeat replay and forgery), [D3-MENCR Message Encryption](https://d3fend.mitre.org/technique/d3f:MessageEncryption/) (protects payload confidentiality), and [D3-NTA Network Traffic Analysis](https://d3fend.mitre.org/technique/d3f:NetworkTrafficAnalysis/) (anomaly detection over the server event stream).
- Standards and vendor sources: LoRa Alliance LoRaWAN L2 1.0.4 and 1.1 specifications and the LoRaWAN security material at [resources.lora-alliance.org](https://resources.lora-alliance.org/); ChirpStack event documentation at [chirpstack.io](https://www.chirpstack.io/); The Things Stack events documentation at [thethingsindustries.com/docs](https://www.thethingsindustries.com/docs/); public rule format reference at [github.com/SigmaHQ/sigma](https://github.com/SigmaHQ/sigma).

**Scope note.** This is a defensive skill. It explains the technique only to the depth needed to detect and mitigate it, ships no capture, replay, or injection tooling, and leaves the verdict to the defender.
