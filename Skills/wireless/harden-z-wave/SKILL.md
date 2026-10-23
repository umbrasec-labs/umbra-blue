---
name: harden-z-wave
description: "Harden Z-Wave home and building automation against network-key capture and RF sniffing on the sub-GHz band. An attacker sniffs device inclusion to recover the network key from legacy S0 (fixed all-zero temporary key) or forces an S2 device down to S0 via the Z-Shave downgrade (MITRE ATT&CK T1040, T1557; ICS T0887, T0860, T0830). Signal lives in controller and hub logs: Z-Wave JS driver logs, Home Assistant device security class, and SmartThings, Hubitat or Z/IP Gateway inclusion records, with Zniffer traces for RF forensics. Gives detectable indicators (S0 or insecure inclusion on S2-capable products, unexpected inclusion windows, bootstrap failures), a hypothesis-driven hunt, and an inclusion hardening plan mapped to ISO 27001 and NIST CSF. Use when hardening a Z-Wave deployment, hunting key capture or downgrade activity, triaging why a node was included at S0 or None, or reviewing SmartStart and DSK provisioning."
---

# Z-Wave Key Capture and Sniffing Exposure - Defensive Methodology

> **Tier 2 - methodology skill.** No bespoke UMBRASEC detection rule ships with this skill yet. It gives the defender's method, the log sources and signals, the hunt, and the S0/S2 key and inclusion hardening, and it points to public rule and standards sources. Promotion to Tier 1 (a sourced, tuned UMBRASEC rule) is tracked in [COVERAGE.md](https://github.com/umbrasec-labs/umbra-blue/blob/main/COVERAGE.md). Do not treat the content below as citing a UMBRASEC rule; there is none for this threat yet.

## TL;DR

Z-Wave security rests on one secret: the network key established when a device is included (paired) into the mesh. The legacy S0 class is the problem. During S0 inclusion the controller sends the network key encrypted under a hardcoded all-zero temporary key, so anyone who captures that brief exchange over RF recovers the network-wide key and can decrypt and inject from then on. S2 fixes this with a Curve25519 ECDH exchange authenticated out of band by the printed Device Specific Key (DSK), but an attacker can try to force an S2-capable device to fall back to S0 during inclusion (the Z-Shave downgrade) and sniff the weaker exchange. You almost never see the radio. You see the controller log recording which security class each node was granted. Watch for one high-value fact: a node included at **S0 or None when the product is S2-capable**. Treat the network key as long-lived shared material, prefer S2 only, provision with SmartStart and DSK, protect the key file that your controller stores at rest, and ship inclusion events to your log store. No single signal is conclusive on a noisy mesh; layer them.

## What it looks like, defender view

The capture happens in a window of seconds during inclusion and leaves nothing on the air you will routinely be watching. The evidence surfaces at the controller, which is the single component that negotiates the security class and holds the keys. A device included under S0 is recorded by the controller as having been granted the `S0_Legacy` class; the network key then moved across the air protected only by the fixed temporary key, so a defender should treat any S0 inclusion of an S2-capable product as a key-exposure event whether or not an attacker was present. A downgrade attempt presents as an S2-capable product that ends up at `S0_Legacy` or at no security at all, often alongside a security-bootstrapping failure in the log where the S2 handshake did not complete. A forced re-inclusion presents as an unexpected move of the controller into inclusion mode, or a known node suddenly re-included. None of this requires the attacker to have broken AES-128; it requires only RF capture during an S0 exchange, or the ability to nudge an inclusion toward S0.

## Log sources and signals

The telemetry is the controller and hub, not the radio. Ship it to your log store.

- **Z-Wave JS driver log and Z-Wave JS UI** (the stack behind Home Assistant, zwave-js-ui, and many open hubs). The driver records the chosen `InclusionStrategy` (`Default`, `Security_S2`, `Security_S0`, `Insecure`, `SmartStart`), the `securityClasses` granted to each node (`S2_AccessControl`, `S2_Authenticated`, `S2_Unauthenticated`, `S0_Legacy`, or none), the DSK validation step, and explicit security-bootstrapping failure lines when an S2 handshake does not complete. Raise the driver log level to capture inclusion detail. Key fields and markers: node ID, `securityClasses`/highest security class, `InclusionStrategy`, inclusion start and stop, bootstrap success or failure.
- **Home Assistant** surfaces the granted security class on each Z-Wave device page, so an audit of device pages is a fast point-in-time check even without log retention.
- **Hub and vendor logs**: SmartThings, Hubitat, Fibaro Home Center, and Silicon Labs Z/IP Gateway / Unify record inclusion events and the per-node security level. Field names differ, but all of them tell you the security class a node negotiated and when inclusion ran.
- **Zniffer** (Silicon Labs' own Z-Wave trace tool) is the defender's RF forensic capture for an incident, letting you confirm after the fact which class an exchange used. It is a diagnostic record, not a live alarm.
- **Key material at rest.** Z-Wave JS stores the network keys (one per S2 class plus the S0 legacy key) as hex strings in its settings or add-on configuration. Any backup, export, or config snapshot that includes those values is itself the key. Track where that file and its backups live; a leaked config is a silent equivalent to a sniffed inclusion.

What normal looks like, so the anomaly is legible: on a healthy modern mesh every security-capable node carries an `S2_*` class, inclusion runs only during deliberate maintenance, security bootstrapping succeeds, and the stored key file sits in one controlled location. An `S0_Legacy` or unsecured node on an S2-capable product, an inclusion outside a maintenance window, a bootstrap failure, or a key file in an unexpected backup are all deviations from that baseline.

## Detection approach

Alert on the controller-side facts, because that is where downgrade and insecure inclusion become visible and where false positives are lowest.

1. **S0 or insecure inclusion of an S2-capable product.** This is the highest-value signal. A node granted `S0_Legacy` or no security class, for a product that supports S2, means the network key was exposed to a weaker exchange, by misconfiguration or by downgrade. Alert on it and investigate whether S2 was available and why it was not used.
2. **Security-bootstrapping failure.** An S2 handshake that starts and fails, especially one followed by an S0 or insecure grant, is the downgrade pattern. Baseline bootstrap failures at near zero and alert on them.
3. **Unexpected inclusion-mode window.** The controller entering inclusion mode, or a node being included or re-included, outside a planned maintenance window is worth an alert in any environment where inclusions are rare and deliberate.
4. **Key-material exposure.** Detect configuration backups or exports that carry the Z-Wave JS key values landing outside their approved location. This is file and data-loss monitoring, not RF, but it closes the same key-exposure gap.

There is no widely maintained public Sigma ruleset dedicated to Z-Wave controller events today, so this skill does not point you at one that does not exist. The practical path is to normalize the Z-Wave JS log or your hub's inclusion events into your log store and author the correlations above against the security-class and inclusion-strategy fields. Use the public SigmaHQ repository ([github.com/SigmaHQ/sigma](https://github.com/SigmaHQ/sigma)) as the format and category reference, the Z-Wave JS documentation ([zwave-js.github.io](https://zwave-js.github.io/zwave-js/)) for the exact strategy and security-class identifiers your deployment emits, and MITRE D3FEND ([d3fend.mitre.org](https://d3fend.mitre.org/)) for the countermeasure framing. A tuned UMBRASEC rule for this threat is not yet shipped; see the Tier 2 banner above.

## Threat hunt

Hypothesis: one or more nodes were included insecurely, or forced down to S0, exposing the network key.

1. Enumerate every node and its granted security class from the controller (the Z-Wave JS device list, or each Home Assistant device page). Flag every node that is `S0_Legacy` or unsecured.
2. For each flagged node, check the product's capability. A node at S0 or None whose product supports S2 is the finding; a genuinely S0-only legacy device is a known-risk inventory item, not an incident, but it still means an S0 key lives on the mesh.
3. Pull inclusion history from the driver or hub log and line up each inclusion with your maintenance records. An inclusion with no matching change ticket, or a re-inclusion of an existing node, is high interest.
4. Pull security-bootstrapping failure lines and correlate them in time with the insecure grants from step 1. A failure immediately before an S0 grant is the downgrade signature.
5. Inventory the key material: find every copy of the Z-Wave JS settings or add-on config and its backups, and confirm none sit outside the controlled location. One stray backup is a key leak.
6. Rank by blast radius: a node that controls a lock, garage, gate, or alarm outranks a light or sensor, because the network key is shared across the mesh and a single capture compromises every node on it, including the locks.

## Hardening

Shrink the key-exposure and inclusion attack surface. Mappings below use control codes grounded in the UMBRASEC [foundation guide](https://umbrasec.dev/guide/foundation.html), [identity and access guide](https://umbrasec.dev/guide/identity-and-access.html), and [detection and response guide](https://umbrasec.dev/guide/detection-and-response.html); a cell is left blank where no single control maps cleanly. The ASD Essential Eight is Windows-estate oriented and maps poorly to a Z-Wave mesh, so most of its column is blank by design, which is honest rather than a gap.

| Control | What it does | Essential Eight | ISO 27001:2022 | NIST CSF 2.0 |
|---|---|---|---|---|
| Require S2, refuse S0 fallback | Removes the all-zero-temporary-key exchange so RF capture of an inclusion yields nothing usable; the controller must prompt before any S0 fallback, so the operator can decline | - | A.8.5 Secure authentication | PR.AA-03 |
| Provision with SmartStart and DSK | Authenticates the device out of band by its printed Device Specific Key or QR, which is what defeats the S2 downgrade and man-in-the-middle during inclusion | - | A.5.17 Authentication information | PR.AA-01 |
| Retire or isolate S0-only devices | An S0-only product keeps a sniffable key on the mesh; replace it, or accept and document the residual risk as an inventory decision | - | A.5.9 Inventory of assets | ID.AM |
| Protect network key material at rest | Keeps the Z-Wave JS key file and its backups in one controlled location with restricted access, so a leaked config is not a silent key compromise | - | A.5.17 Authentication information | PR.DS |
| Keep controller and hub firmware current | Closes known inclusion and security-bootstrapping defects and keeps the S2 implementation up to date | Patch operating systems (firmware) | A.8.8 Technical vulnerabilities | PR.PS |
| Restrict who can trigger inclusion | Limits inclusion to authorized operators and planned windows, so a forced or stray inclusion is anomalous by construction | - | A.8.2 Privileged access rights | PR.AA-05 |
| Log and monitor inclusion and security class | Turns the signals above into alerts rather than facts nobody reads | - | A.8.15 Logging; A.8.16 Monitoring | DE.CM; DE.AE |

Note on inclusion exposure: do not rely on performing inclusion "quietly" or at low power as a mitigation. Only the initial node information frame is low power; the network-wide inclusion that carries the key exchange runs at full power across the mesh and is sniffable at range. The fix is refusing S0, not hiding the exchange.

## Honest limitations

This method watches the controller, so it cannot see a purely passive attacker who captures an S0 inclusion and never transmits; the capture leaves no controller-side trace, and the defense against it is S2 and never exposing an S0 exchange, not detection. Once the network key is captured, there is no per-node fix: the key is shared across the whole mesh, so recovery means generating new keys on the controller and re-including every node, not re-pairing one device. A genuinely S0-only legacy product will keep showing as S0 for benign reasons, so that signal flags risk rather than proving an attack. If you do not raise the Z-Wave JS log level, inclusion and bootstrap detail may not be recorded, leaving a blind spot. Security-class audits are point-in-time; without log retention you can see today's state but not when or how a node reached it. Treat every signal as evidence to weigh, baseline in report-only mode first, and leave the final call to the defender.

## ATT&CK and D3FEND

- MITRE ATT&CK (Enterprise): [T1040 Network Sniffing](https://attack.mitre.org/techniques/T1040/), [T1557 Adversary-in-the-Middle](https://attack.mitre.org/techniques/T1557/) (the S2-to-S0 downgrade is an adversary-in-the-middle manipulation of the inclusion handshake).
- MITRE ATT&CK (ICS): [T0887 Wireless Sniffing](https://attack.mitre.org/techniques/T0887/), [T0860 Wireless Compromise](https://attack.mitre.org/techniques/T0860/), [T0830 Adversary-in-the-Middle](https://attack.mitre.org/techniques/T0830/).
- MITRE D3FEND: Message Authentication (the out-of-band DSK authenticates the device during S2 inclusion and defeats downgrade and injection), Message Encryption (S2 session keys protect payload confidentiality), and Network Traffic Analysis (anomaly detection over the controller inclusion and security-class events). See [d3fend.mitre.org](https://d3fend.mitre.org/).
- Standards and vendor sources: ITU-T G.9959 (the Z-Wave PHY/MAC) and the Z-Wave Alliance security specifications at [z-wavealliance.org](https://z-wavealliance.org/); Silicon Labs Z-Wave security and S2 documentation; Z-Wave JS documentation at [zwave-js.github.io](https://zwave-js.github.io/zwave-js/); public rule format reference at [github.com/SigmaHQ/sigma](https://github.com/SigmaHQ/sigma). The S2 downgrade is documented in Pen Test Partners' "Z-Shave" research (2018), and early Z-Wave key-exchange weaknesses in SensePost's Black Hat USA 2013 work on Z-Wave; both are cited for defensive context only.

**Scope note.** This is a defensive skill. It explains the technique only to the depth needed to detect and mitigate it, ships no sniffing, downgrade, or key-recovery tooling, and leaves the verdict to the defender.
