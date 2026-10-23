---
name: harden-wpa2
description: "Defend WPA/WPA2-PSK networks against four-way handshake (EAPOL) or PMKID capture and offline cracking of the pre-shared key, often preceded by a deauthentication burst that forces reconnects (MITRE ATT&CK T1040, T1110.002; deauth relates to T1498). Detection lives at the wireless layer: WLAN controller and WIDS/WIPS events (Cisco Catalyst 9800 aWIPS, Aruba RFProtect, Meraki Air Marshal), AP syslog and SNMP traps, and 802.11 management frames from a monitor-mode sensor. Gives the defender view of the capture, the log sources that carry the signal, a reconnection-storm and PMKID-harvest hunt, and hardening toward a strong unique passphrase, WPA3-SAE, and 802.11w Protected Management Frames. Use when hardening Wi-Fi against handshake capture, writing a PSK passphrase policy, hunting deauthentication floods or PMKID harvesting, triaging WIDS deauth alerts, or deciding whether to move off WPA2-Personal."
---

# WPA/WPA2-PSK Handshake Capture - Defensive Methodology

> **Tier 2 - methodology skill.** No bespoke UMBRASEC detection rule ships with this skill yet. It gives the defender's method, the log sources and signals, the hunt, and the hardening, and points to public rule sources. Promotion to Tier 1 (a sourced, tuned UMBRASEC rule) is tracked in [COVERAGE.md](https://github.com/umbrasec-labs/umbra-blue/blob/main/COVERAGE.md). Do not treat the content below as citing a UMBRASEC rule; there is none for this threat yet.

WPA2-Personal protects a network with a single pre-shared key, and every client derives its session keys from that one secret during the four-way handshake. Anyone who captures that handshake, or a PMKID the access point leaks during association, can guess the passphrase offline at full GPU speed with no further contact and no lockout. This skill is defensive: it explains the technique only as far as detection and mitigation require, and ships no capture or cracking tooling.

## TL;DR for defenders

The crack happens offline and is invisible to your network. What you can see is the noise an attacker makes to get the material: a burst of **deauthentication** frames that knocks clients off so they re-handshake, or a lone association that reaches **EAPOL message 1** (carrying a PMKID) and then vanishes. Enable your controller's **WIDS/WIPS** deauth and EAPOL-flood signatures, forward WLAN controller syslog to your SIEM, and alert on broadcast deauths with **reason code 7 or 1**. The durable fixes are not detections: a long random unique passphrase that is not practically crackable, **802.11w Protected Management Frames** so spoofed deauths are rejected, and migration to **WPA3-SAE**, which makes a captured handshake useless for offline guessing.

## What it looks like, defender view

The offline crack produces no on-network telemetry at all, and passive capture of a naturally occurring handshake is radio-only and leaves no trace on your wire. Two enabling steps are what surface in telemetry. First, to avoid waiting for a client to reconnect on its own, an attacker sends spoofed deauthentication or disassociation frames (802.11 management, type 0) so a client drops and immediately re-runs the four-way handshake in range of the capture radio: this shows up as a reconnection storm. Second, the PMKID variant needs no client and no deauth; the access point may hand a PMKID to a single association request, so it presents as an association that completes EAPOL M1 and then never finishes M2 to M4, often repeated across many BSSIDs from one transient MAC. An evil-twin or rogue access point beaconing your SSID can harvest handshakes entirely off your infrastructure, which is why rogue-AP detection belongs in the same picture.

## Log sources and signals

Detection for this threat lives at the wireless layer, not the host log. The signal-bearing sources:

- **WLAN controller WIDS/WIPS events.** Cisco Catalyst 9800 WLC with **aWIPS** (via Catalyst Center / DNA Center) raises signatures such as *Deauthentication flood*, *Broadcast deauth*, *Disassociation flood*, and *EAPOL flood*. Aruba/HPE **RFProtect** IDS raises *Deauth Broadcast*, *Disconnect Station Attack*, and EAP/handshake-flood events. Cisco Meraki **Air Marshal**, Juniper Mist, and Ubiquiti UniFi expose equivalents.
- **AP and controller syslog / SNMP traps.** Client dot11 deauthenticate events with an 802.11 reason code, and rapid associate/deauthenticate cycles for many clients on one BSSID within seconds. Forward these to the SIEM.
- **Raw 802.11 management frames** from a monitor-mode sensor or PCAP. Key fields:
  - Frame type/subtype: deauthentication is subtype `0x0c`, disassociation `0x0a` (tshark `wlan.fc.type_subtype == 0x0c`).
  - `wlan.fixed.reason_code`: reason **7** (class 3 frame from a nonassociated station) and **1** (unspecified) dominate forged-deauth floods; **2**, **4** (inactivity), **8** (STA leaving), and **15** (four-way-handshake timeout) occur benignly.
  - Destination address `ff:ff:ff:ff:ff:ff` on a deauth is a broadcast deauth, which no healthy AP sends in volume.
  - `eapol`: presence and sequence of the four handshake messages; many partial handshakes or M1-only exchanges, and the RSN information element carrying a **PMKID** in M1.
- **PMF / 802.11w events.** Where Protected Management Frames are enabled, spoofed unprotected deauths are dropped; the controller logs invalid-MIC management frames and SA Query timeouts, which are themselves a tamper signal.

Normal baseline: clients roam and reconnect constantly, so isolated deauths (reason 4 or 8) and steady handshakes are routine. The anomaly is volume, broadcast scope, reason code 7/1, and many clients dropped simultaneously on a single AP.

## Detection approach

Alert on the reconnection storm, not the crack. The high-value signal is a burst of deauthentication or disassociation frames, especially broadcast and especially reason code 7 or 1, followed within seconds by reassociations and fresh four-way handshakes on the same BSSID; and, for the clientless path, associations that reach EAPOL M1 (PMKID present) and never complete. Because this signal is produced and consumed at the controller/radio layer rather than in OS event logs, classic SIEM-log rule coverage is thin and there is **no tuned UMBRASEC rule for this threat yet**. Use the public sources below rather than inventing one:

- Enable and tune your vendor's WIDS signatures (Cisco aWIPS deauth/EAPOL-flood signatures; Aruba RFProtect IDS profile). These are the primary detector.
- **nzyme** (https://www.nzyme.org/), an open-source WiFi defense platform, monitors for deauth/disassoc floods, PMF bypass, and rogue/evil-twin APs from dedicated sensors.
- **Kismet** (https://www.kismetwireless.net/) raises WIDS alerts including `DEAUTHFLOOD` and `BCASTDISCON`.
- **Wireshark / tshark** display filters for retrospective PCAP review, e.g. `wlan.fc.type_subtype == 0x0c && wlan.fixed.reason_code == 7`, and `eapol` to confirm which handshake messages were captured.
- Forward WLAN controller syslog and traps to the SIEM and write a correlation on deauth-reason-code storms. **SigmaHQ** (https://github.com/SigmaHQ/sigma) is the place to check for community network rules, but 802.11 coverage there is limited and typically needs a vendor-specific parser.
- **MITRE D3FEND D3-NTA Network Traffic Analysis** (https://d3fend.mitre.org/technique/d3f:NetworkTrafficAnalysis/) frames this monitoring countermeasure.

## Threat hunt

Hypothesis: an attacker forced a reconnect to capture a handshake, or harvested a PMKID, within the retention window.

1. From controller/sensor data over the window, pull all deauthentication and disassociation management frames. Group by BSSID and `reason_code`. Flag bursts of broadcast (`ff:ff:ff:ff:ff:ff`) deauths with reason 7 or 1, or many distinct client MACs dropped within a few seconds on one AP.
2. For each burst, pull the reassociations and EAPOL four-way handshakes that follow within seconds on that BSSID. That pairing is the likely capture window; note the client MACs involved.
3. For the clientless path, search associations that reach EAPOL M1 (RSN IE with a PMKID) but never complete M2 to M4, especially from unfamiliar or short-lived MACs, and especially the same radio touching many BSSIDs.
4. Cross-check PMF: deauth-forced captures succeeding against an SSID that should enforce 802.11w mean PMF is off or in transition/optional mode. Treat that as a configuration finding.
5. Look for rogue or evil-twin APs beaconing your SSID on another channel or BSSID (nzyme bandit detection, Air Marshal). A karma/evil-twin harvests handshakes without ever touching your real AP, so it will not appear in step 1.

## Hardening

Detection buys awareness; these changes shrink or remove the attack surface. The passphrase controls below map cleanly to the UMBRASEC [identity and access guide](https://umbrasec.dev/guide/identity-and-access.html), which follows NIST SP 800-63B and ASD's ISM for long passphrases (no forced periodic rotation; screen against breached-password lists). The remaining controls are protocol and segmentation measures that no single framework code maps to one-for-one, so they are stated in prose rather than forced into the table.

| Control | What it does | Essential Eight | ISO 27001:2022 | NIST CSF 2.0 |
|---|---|---|---|---|
| Strong, unique Wi-Fi passphrase (long, random, not a dictionary word) | Pushes offline PSK cracking past practical reach; the only PSK defence that works even after capture | - | A.5.17 Authentication information | PR.AA-01 |
| Change the vendor default PSK and AP admin password | Removes the default-key-generator shortcut that bypasses cracking entirely | - | A.5.17 Authentication information | PR.AA-01 |

Beyond the passphrase (D3FEND D3-SPP Strong Password Policy, and D3-CDP Change Default Password for the default-key case):

- **Enable 802.11w Protected Management Frames (PMF).** Required in WPA3, optional in WPA2. With PMF, spoofed deauth/disassoc frames are rejected, so the deauth-forced capture path fails and generates SA Query / invalid-MIC events instead.
- **Migrate to WPA3-Personal (SAE).** Simultaneous Authentication of Equals replaces the crackable PSK handshake with a key exchange that gives an attacker no offline-guessable material from a capture. Use WPA2/WPA3 transition mode during rollout, then disable WPA2 fallback once clients support SAE.
- **Disable WPS.** PIN and push-button setup are a separate, well-known key-recovery path.
- **Consider WPA2/WPA3-Enterprise (802.1X/EAP)** for higher assurance: per-user credentials and no shared key means there is no single PSK to capture and crack.
- **Segment guest and IoT onto their own SSID/VLAN** with its own key and client isolation, so a cracked key on one network does not expose the rest.

## Honest limitations

The offline crack and passive capture of a natural handshake leave no telemetry; you can only catch the noisy enabling steps, and only if you run WIDS or sensors. A patient attacker who waits for a client to reconnect on its own, or who harvests a PMKID with no deauth, may produce nothing to alert on. WIDS coverage is spatial: a sensor sees only its RF neighborhood, so an attacker at range or with a directional antenna from outside the building can be invisible. PMF defeats deauth-forced capture but does not stop PMKID leakage on affected APs, nor passive capture, so the durable control remains passphrase strength plus WPA3-SAE. Evil-twin capture happens off your infrastructure entirely. No bespoke UMBRASEC rule ships for this threat; vendor WIDS signatures and open-source sensors are the detection substrate, and the hardening does more than the detection here.

## ATT&CK and D3FEND

- MITRE ATT&CK: [T1040 Network Sniffing](https://attack.mitre.org/techniques/T1040/) (Credential Access, Discovery) for the over-the-air capture; [T1110.002 Password Cracking](https://attack.mitre.org/techniques/T1110/002/) (Credential Access) for the offline PSK crack. The deauthentication burst used to force a reconnect relates to [T1498 Network Denial of Service](https://attack.mitre.org/techniques/T1498/).
- MITRE D3FEND: [D3-SPP Strong Password Policy](https://d3fend.mitre.org/technique/d3f:StrongPasswordPolicy/) and its subclass [D3-CDP Change Default Password](https://d3fend.mitre.org/technique/d3f:ChangeDefaultPassword/) for the passphrase controls; [D3-NTA Network Traffic Analysis](https://d3fend.mitre.org/technique/d3f:NetworkTrafficAnalysis/) for the monitoring.
- Public rule and tool sources: SigmaHQ (https://github.com/SigmaHQ/sigma), nzyme (https://www.nzyme.org/), Kismet (https://www.kismetwireless.net/), Wireshark/tshark 802.11 filters, and vendor WIDS (Cisco aWIPS, Aruba RFProtect). Standards: IEEE 802.11w (PMF), Wi-Fi Alliance WPA3-SAE, NIST SP 800-63B.

**Scope note.** This is a defensive skill. It explains the technique only to the depth needed to detect and mitigate it and deliberately provides no handshake-capture or cracking tooling. UMBRASEC publishes defense, not offense.
