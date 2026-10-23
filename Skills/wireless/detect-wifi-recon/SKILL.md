---
name: detect-wifi-recon
description: "Detection and response methodology for 802.11 wireless reconnaissance: wardriving and rogue scanners, hidden-SSID discovery through directed probing, and probe-request flooding used to enumerate clients and their preferred network lists (MITRE ATT&CK T1595, T1040; related T1590). The signal is radio-layer: wireless IDS/IPS and controller telemetry such as Kismet NETSTUMBLER and WELLENREITER alerts, Cisco aWIPS, Meraki Air Marshal, Aruba/HPE WIP, and raw monitor-mode captures of probe and beacon frames. The skill gives the frame-level signal, log sources, a hunt over probe volume and per-MAC fan-out, and hardening that shrinks the recon surface. Use when investigating unexplained wireless scanning, triaging a wireless IDS scanner or probe-flood alert, hunting for wardriving or evil-twin reconnaissance, writing wireless recon detections, or hardening WLANs against SSID and client enumeration."
---

# 802.11 Wireless Reconnaissance - Defensive Methodology

> **Tier 2 - methodology skill.** No bespoke UMBRASEC detection rule ships with this skill yet. It gives the defender's method, the log sources and signals, and the hardening, and points to public rule and sensor sources. Promotion to Tier 1 (a sourced, tuned UMBRASEC rule) is tracked in [COVERAGE.md](https://github.com/umbrasec-labs/umbra-blue/blob/main/COVERAGE.md). Do not treat the content below as citing a UMBRASEC rule; there is none for this threat yet.

## TL;DR

Wireless reconnaissance is the first phase of most WLAN attacks: an attacker maps your airspace before they touch it. Passive recon listens for beacons (management subtype `0x08`) and probe responses (`0x05`) to enumerate SSIDs, BSSIDs, channels, and clients. Active recon transmits probe requests (`0x04`) to force hidden networks to reveal themselves and to elicit client responses. Probe-request flooding pushes that to volume, harvesting the preferred network lists (PNLs) clients broadcast so an attacker can later stand up a matching evil twin. None of this appears in endpoint or Windows logs; the signal lives in the radio layer. Watch your wireless IDS/IPS and controllers for scanner and probe-flood signatures (Kismet `NETSTUMBLER` and `WELLENREITER`; Cisco aWIPS and Meraki Air Marshal scanner/probe detections; Aruba WIP active-probe signatures), and shrink the recon surface with WPA3/PMF, probe-response hygiene, and per-SSID client isolation. This skill is defensive and ships no scanning, wardriving, or probe-injection tooling.

## What it looks like, defender view

In telemetry, recon shows up as a station that observes far more than it participates. A rogue scanner hops channels rapidly and transmits broadcast (NULL-SSID) probe requests addressed to no particular network, soaking up every beacon and probe response in range without ever associating. Hidden-SSID discovery shows as directed probe requests naming an SSID you deliberately do not beacon, usually followed immediately by the AP's probe response that discloses it. Probe flooding shows as one source MAC emitting a sustained stream of probe requests at a rate no real client produces, often cycling through many SSID names drawn from captured PNLs. The telling pattern is asymmetry: lots of listening and probing, little or no authentication or association, and MAC addresses that never appear in your client inventory. Because modern clients randomize their MAC during probing, a scanner that uses a single fixed MAC across a long channel sweep is itself anomalous.

## Log sources and signals

The detection is radio-layer, not host-layer. Use one or more of:

- **Wireless IDS/IPS sensors.** [Kismet](https://kismetwireless.net/docs/readme/alerts/alerts/) historically raises `NETSTUMBLER` (the NetStumbler active-scan probe signature) and `WELLENREITER` (the Wellenreiter scanner signature), and logs every probe request it sees with source MAC and requested SSID, which is the raw material for probe-flood and hidden-SSID hunting. Alert rate limits are set in `kismet_alerts.conf` via the `alert=` option, and Kismet writes a PCAP you can open in Wireshark to confirm.
- **Enterprise controllers / cloud WLAN.** Cisco Catalyst 9800 and WLC with Advanced Wireless IPS (aWIPS) ship scanner and probing threat signatures (including NetStumbler-style detection and device-probing/AP-flood signatures); Aruba/HPE ArubaOS Wireless Intrusion Protection (WIP) includes active-802.11-probe, NetStumbler, and Wellenreiter detections; Cisco Meraki Air Marshal and Ubiquiti UniFi surface rogue-device and scanning events. Forward these to the SIEM as syslog and alert on the scanner/probe signature plus the offending source MAC, channel, and sensor.
- **Raw 802.11 capture (confirmation and hunt).** With a monitor-mode interface, Wireshark/tshark display filters isolate the frames: `wlan.fc.type_subtype == 0x04` (probe request), `wlan.fc.type_subtype == 0x05` (probe response), and `wlan.fc.type_subtype == 0x08` (beacon). The requested network is in `wlan.ssid` (empty for a broadcast/NULL probe). Count by `wlan.sa` (source MAC) over time, and watch for directed probes whose `wlan.ssid` matches an SSID you do not beacon.

What normal looks like: real clients emit probe requests too, in modest bursts when roaming, waking, or searching for known networks, and background wardriving from passing devices is part of any urban RF environment. The anomaly is a single source producing sustained, high-rate, broadly-directed probing with little or no association, a directed probe for an SSID that should be hidden, or a scanner signature firing from a MAC that is not one of your managed clients.

## Detection approach

Alert on behaviour and breadth, not on a single probe. The high-signal conditions are: (1) a wireless IDS/IPS scanner signature firing (Kismet `NETSTUMBLER`/`WELLENREITER`, or the vendor aWIPS/WIP/Air Marshal equivalents), which flags recognised scanning tools directly; (2) a single source MAC whose probe-request count over a short window exceeds a learned per-client baseline, especially when the requests cycle through many distinct SSID names; and (3) a directed probe request, or its matching probe response, naming an SSID you deliberately do not broadcast, sent by a MAC that is not one of your managed clients, which indicates an outsider already knows or is testing the hidden network name. Prefer the purpose-built wireless IDS/IPS signatures above, because 802.11 management frames are not log events and are a poor fit for log-oriented rule formats; Sigma and similar operate on the controller/syslog records the sensors emit, not on the frames themselves. A tuned UMBRASEC rule is not yet shipped for this threat; for maintained public detections use the vendor aWIPS/WIP/Air Marshal signatures, Kismet's `kismet_alerts.conf` and its probe-request logging, and track any SIEM-side controller-log rules in the general [SigmaHQ repository](https://github.com/SigmaHQ/sigma).

## Threat hunt

Hypothesis: an attacker is performing wireless reconnaissance against our airspace, sweeping for APs, uncloaking a hidden SSID, or harvesting client PNLs ahead of an evil twin.

1. Pull a window of wireless-controller syslog and IDS alerts; surface any scanner signatures (NetStumbler/Wellenreiter style) and note the source MAC, channel span, and sensor. A device seen across many channels from a single MAC in a tight window is sweeping.
2. From Kismet or a monitor-mode PCAP, count probe requests (`wlan.fc.type_subtype == 0x04`) grouped by `wlan.sa`. Rank by rate per minute and by the number of distinct `wlan.ssid` values each MAC requests. A real client sits near the floor and asks for a few known SSIDs; a flooder or scanner spikes on both axes.
3. Filter for directed probes and probe responses whose `wlan.ssid` equals any SSID you intentionally hide. First exclude MACs in your managed-client inventory, since your own clients probe for the hidden SSID by name; a hit from any other MAC means the SSID is already known to an outsider, so treat that MAC as a recon source.
4. Join suspect source MACs against your managed-client inventory and DHCP/RADIUS records. A probing MAC that never authenticates, never associates, and is not in inventory is a strong recon indicator. Factor in that attackers can randomize or spoof the MAC, so a fixed MAC that persists across a long sweep is the suspicious case, not the reassuring one.
5. Correlate recon timing with any later same-SSID AP appearing on a different channel or with anomalous signal strength; recon that precedes a new matching AP is an evil-twin setup, which the sibling rogue-AP methodology covers.

## Hardening

Shrink the recon surface and make what leaks less useful. The practical controls are mostly RF and WLAN configuration rather than named framework items:

- **Do not rely on SSID cloaking as a security control.** Hiding an SSID only removes it from beacons; directed probing reveals it immediately, and cloaking forces your own clients to actively probe for the network, broadcasting its name everywhere they roam. Treat a hidden SSID as obfuscation, not defence, and never as a reason to weaken authentication.
- **Enforce WPA3 and 802.11w Protected Management Frames.** PMF does not stop passive listening, but it blocks the spoofed-frame follow-ons that recon enables and raises the cost of pivoting from enumeration to an active attack. WPA3 and Enhanced Open mandate PMF.
- **Reduce probe-response exposure.** Trim transmit power and tune AP placement so coverage does not spill far beyond your premises, and use band steering/minimum-RSSI so distant scanners get fewer useful responses. Enable client (peer-to-peer) isolation on guest and client SSIDs so enumeration of one client does not map the rest.
- **Run an always-on wireless IDS/IPS.** Continuous radio-layer monitoring is the only way recon is visible at all; without it these frames never reach your SIEM. This is the control that maps cleanly to the governance frameworks.

Only the continuous-monitoring control grounds cleanly in the UMBRASEC [detection and response guide](https://umbrasec.dev/guide/detection-and-response.html); the RF and WLAN-configuration controls above have no single clean framework code, so they are given as prose rather than invented into the table.

| Control | Essential Eight | ISO 27001:2022 | NIST CSF 2.0 |
|---|---|---|---|
| Always-on wireless IDS/IPS with alerts forwarded to the SIEM | - | A.8.15 Logging; A.8.16 Monitoring activities | DE.CM Continuous monitoring; DE.AE Adverse events |

## Honest limitations

Passive reconnaissance is fundamentally hard to detect, because a receive-only listener transmits nothing: pure wardriving that only collects beacons and probe responses may leave no signal at all, and the detections here lean on the active half (probing, scanning tools, probe floods). Widespread MAC randomization cuts both ways: it limits an attacker's client-tracking but also means per-MAC counting undercounts a careful scanner that rotates addresses, so thresholds will miss a low-and-slow or address-hopping operator. Scanner signatures recognise known tools by their fingerprint and are evaded by custom or updated tooling. Detection depends entirely on radio-layer visibility; with no wireless IDS/IPS and no controller scanner signatures, wireless recon is invisible to a conventional SIEM. Baselines are environment-specific and noisy in dense urban RF, where third-party devices probe constantly, so treat the directed-probe-for-a-hidden-SSID case and a persistent fixed-MAC channel sweep as the higher-confidence signals and tune volume thresholds per site. Source MACs are spoofable, so they identify a behaviour, not a person.

## ATT&CK and D3FEND

- MITRE ATT&CK: [T1595 Active Scanning](https://attack.mitre.org/techniques/T1595/) (Reconnaissance) for active probing, hidden-SSID discovery, and probe flooding; [T1040 Network Sniffing](https://attack.mitre.org/techniques/T1040/) (Discovery, Credential Access) for passive collection of beacons and probe responses. Related: [T1590 Gather Victim Network Information](https://attack.mitre.org/techniques/T1590/) (Reconnaissance), since the goal of recon is building a picture of the target network.
- MITRE D3FEND: [D3-NTA Network Traffic Analysis](https://d3fend.mitre.org/technique/d3f:NetworkTrafficAnalysis/) for the scanner/probe-flood detection side.
- Public rule and sensor sources: [Kismet WIDS alerts](https://kismetwireless.net/docs/readme/alerts/alerts/) (NETSTUMBLER, WELLENREITER, and probe-request logging); Cisco Catalyst 9800 / aWIPS and Meraki Air Marshal documentation; Aruba/HPE ArubaOS Wireless Intrusion Protection (WIP) documentation; [SigmaHQ repository](https://github.com/SigmaHQ/sigma) for controller-log rules.

**Scope note.** This is a defensive skill. It explains wireless reconnaissance only to the depth needed to detect and mitigate it and deliberately provides no scanning, wardriving, hidden-SSID discovery, or probe-injection tooling. UMBRASEC publishes defense, not offense.
