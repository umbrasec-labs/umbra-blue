---
name: detect-deauth
description: "Detection and response methodology for 802.11 deauthentication and disassociation flooding, a wireless denial-of-service that spoofs management frames to knock clients off an AP and often precedes an evil twin or handshake capture (MITRE ATT&CK T1498, T1498.001; enabling T1557). Signals come from wireless IDS/IPS and controller telemetry: Kismet DEAUTHFLOOD / BCASTDISCON alerts, Cisco Catalyst 9800 aWIPS, Aruba/HPE WIP, Meraki Air Marshal, and raw 802.11 captures. The skill gives the frame-level signal, log sources to watch, a hunt over reason codes and source rate, and 802.11w Protected Management Frames hardening. Use when investigating repeated Wi-Fi client drops, triaging a wireless IDS deauth or disassoc alert, hunting for an evil-twin precursor, writing wireless DoS detections, or hardening WLANs with 802.11w / WPA3 PMF."
---

# 802.11 Deauth / Disassoc Flooding - Defensive Methodology

> **Tier 2 - methodology skill.** No bespoke UMBRASEC detection rule ships with this skill yet. It gives the defender's method, the log sources and signals, and the hardening, and points to public rule and sensor sources. Promotion to Tier 1 (a sourced, tuned UMBRASEC rule) is tracked in [COVERAGE.md](https://github.com/umbrasec-labs/umbra-blue/blob/main/COVERAGE.md). Do not treat the content below as citing a UMBRASEC rule; there is none for this threat yet.

## TL;DR

Unprotected 802.11 management frames carry no authentication, so a deauthentication (subtype `0x0c`) or disassociation (subtype `0x0a`) frame spoofed from the AP's BSSID forces a client to disconnect. Flooding them is a denial of service and is frequently the first move before an evil twin or a WPA handshake capture. You cannot see this in endpoint or Windows logs; the signal lives in the radio layer. Watch your wireless IDS/IPS and controller for deauth/disassoc flood alerts (Kismet `DEAUTHFLOOD`, `BCASTDISCON`, `DISASSOCTRAFFIC`; Cisco aWIPS and Catalyst 9800 deauth-flood signatures; Aruba WIP; Meraki Air Marshal), and close the hole for good with **802.11w Protected Management Frames**, mandatory under WPA3. This skill is defensive and ships no frame-injection or jamming tooling.

## What it looks like, defender view

Clients repeatedly drop and re-associate to an SSID over a short window, often in bursts, while the AP itself reports itself as healthy. In a raw capture you see a surge of deauthentication or disassociation frames whose transmitter address is the legitimate BSSID (spoofed) but whose volume and timing are nothing like the handful a busy AP emits normally. Broadcast deauths (destination `ff:ff:ff:ff:ff:ff`) knock every client off at once. Reason codes are frequently `7` (Class 3 frame received from nonassociated station) or `1` (unspecified), repeated far faster than any benign roaming event. If an evil twin follows, you will also see a second AP beaconing the same SSID on a different channel or with a stronger signal.

## Log sources and signals

The detection is radio-layer, not host-layer. Use one or more of:

- **Wireless IDS/IPS sensors.** [Kismet](https://kismetwireless.net/docs/readme/alerts/alerts/) raises `DEAUTHFLOOD` (deauth/disassoc flood from or to an AP), `BCASTDISCON` (broadcast deauth/disassoc, which no legitimate AP sends in bulk), and `DISASSOCTRAFFIC`. Alert rate limits are set in `kismet_alerts.conf` via the `alert=` option. Kismet also writes a PCAP you can open in Wireshark to confirm.
- **Enterprise controllers / cloud WLAN.** Cisco Catalyst 9800 and WLC with Advanced Wireless IPS (aWIPS) ship a "Deauthentication Flood" / "Broadcast Deauthentication" signature; Aruba/HPE ArubaOS Wireless Intrusion Protection (WIP) has deauth-broadcast and disconnect-station detections; Cisco Meraki Air Marshal and Ubiquiti UniFi surface rogue-AP and containment events. Forward these to the SIEM as syslog and alert on the flood signature plus the offending BSSID/channel.
- **Raw 802.11 capture (confirmation and hunt).** With a monitor-mode interface, Wireshark/tshark display filters isolate the frames: `wlan.fc.type_subtype == 0x0c` (deauthentication), `wlan.fc.type_subtype == 0x0a` (disassociation), and `wlan.fixed.reason_code` for the reason value. Count by `wlan.sa` / `wlan.ta` and `wlan.da` over time.

What normal looks like: APs do emit occasional deauth/disassoc frames during legitimate roaming, idle timeout, or load balancing, but at low single-digit rates per client and almost never as sustained broadcast storms. The anomaly is rate and breadth, not the frame type existing at all.

## Detection approach

Alert on volume and breadth, not on a single frame. The high-signal conditions are: (1) a count of deauth or disassoc frames for a given BSSID that exceeds a learned per-AP baseline in a short window (for example tens of frames in a few seconds); (2) any broadcast-destination deauth/disassoc, which legitimate APs effectively never send in bulk; and (3) deauth/disassoc volume that coincides with a new AP advertising an existing SSID (evil-twin precursor). Prefer the purpose-built wireless IDS/IPS signatures above, because 802.11 management frames are not log events and are a poor fit for log-oriented rule formats; Sigma and similar operate on the controller/syslog records, not on the frames themselves. A tuned UMBRASEC rule is not yet shipped for this threat; for maintained public detections use the vendor aWIPS/WIP/Air Marshal signatures and Kismet's `kismet_alerts.conf` (mainstream Suricata and Snort do not decode or inspect 802.11 management frames), and track any SIEM-side controller-log rules in the general [SigmaHQ repository](https://github.com/SigmaHQ/sigma).

## Threat hunt

Hypothesis: an attacker is flooding deauth/disassoc frames to disrupt a WLAN or to force clients onto a rogue AP.

1. Pull a window of wireless-controller syslog and any IDS alerts; group by BSSID and by detecting-AP/channel. Rank by deauth and disassoc counts per minute. A legitimate AP sits near the floor; a flooded or spoofed BSSID spikes.
2. For the top BSSIDs, open the corresponding Kismet or controller PCAP in Wireshark and apply `wlan.fc.type_subtype == 0x0c || wlan.fc.type_subtype == 0x0a`. Look for a tight cluster of frames with a single repeated `wlan.fixed.reason_code` (commonly `7` or `1`) and for broadcast destinations.
3. Correlate timing with client-side disconnects and with any newly seen AP beaconing the same SSID on a different channel or with anomalous signal strength. A flood that lines up with a new same-SSID AP is an evil-twin setup, not just a nuisance DoS.
4. Check whether the affected WLAN has 802.11w enabled. On a PMF-protected SSID, spoofed deauths should be rejected by clients and the flood should fail to disconnect them, which itself is a useful discriminator between a real attack and a misbehaving client.

## Hardening

The decisive control is **802.11w Protected Management Frames (PMF)**, introduced in IEEE 802.11w-2009, rolled into IEEE 802.11-2012, and carried forward in IEEE 802.11-2020. PMF cryptographically protects unicast deauth/disassoc frames and, via the Broadcast/Multicast Integrity Protocol (BIP) and the Integrity Group Temporal Key (IGTK) exchanged in the key handshake, the broadcast ones, so a frame spoofed from the AP's BSSID without the key is dropped and the client stays associated. Set PMF to Required (MFPR) where client support allows, and Capable/optional (MFPC) as a transition; WPA3 and Enhanced Open mandate PMF, so moving SSIDs to WPA3 enforces it. Be aware that older IoT and VoIP clients may not support PMF Required, so stage it per-SSID. Pair PMF with an always-on wireless IDS/IPS so that floods which aim to disrupt rather than to spoof a specific session are still seen, and so RF-level attacks PMF cannot stop are at least detected. Because the clean framework mapping available in the UMBRASEC [detection and response guide](https://umbrasec.dev/guide/detection-and-response.html) covers logging and monitoring (ISO 27001:2022 A.8.15, A.8.16; NIST CSF 2.0 DE.CM, DE.AE) rather than wireless management-frame cryptography, no Essential Eight / ISO / NIST control maps cleanly onto the PMF control itself, and a framework table is deliberately omitted here rather than invented.

## Honest limitations

PMF stops spoofed deauth/disassoc frames, but it does not stop a determined attacker from denying service another way: RF jamming, a flood of association or authentication requests, spoofed Channel Switch Announcements, or brute-force on the SA Query exchange are all outside what 802.11w protects. It also cannot help pre-association or on legacy SSIDs you cannot move to WPA3. Detection depends entirely on having radio-layer visibility; if you run no wireless IDS/IPS and your controller emits no flood signatures, these attacks are invisible to a conventional SIEM. Baselines are environment-specific: busy roaming networks emit more legitimate deauth/disassoc than quiet ones, so tune per-AP thresholds and treat broadcast deauths as the near-binary high-confidence signal. The frame transmitter address is spoofable, so it identifies the impersonated AP, not the attacker.

## ATT&CK and D3FEND

- MITRE ATT&CK: [T1498 Network Denial of Service](https://attack.mitre.org/techniques/T1498/) and [T1498.001 Direct Network Flood](https://attack.mitre.org/techniques/T1498/001/) (Impact). Deauth flooding frequently enables [T1557 Adversary-in-the-Middle](https://attack.mitre.org/techniques/T1557/) by forcing clients onto an evil-twin AP.
- MITRE D3FEND: [D3-NTA Network Traffic Analysis](https://d3fend.mitre.org/technique/d3f:NetworkTrafficAnalysis/) for the flood-detection side. 802.11w PMF is best read as a cryptographic message-integrity hardening of management frames rather than a single named D3FEND technique.
- Public rule and sensor sources: [Kismet WIDS alerts](https://kismetwireless.net/docs/readme/alerts/alerts/); Cisco Catalyst 9800 / aWIPS and Meraki Air Marshal documentation; [Aruba/HPE Protected Management Frames guidance](https://arubanetworking.hpe.com/techdocs/aos/wifi-design-deploy/security/features/pmf/); [SigmaHQ repository](https://github.com/SigmaHQ/sigma) for controller-log rules.

**Scope note.** This is a defensive skill. It explains deauth/disassoc flooding only to the depth needed to detect and mitigate it and deliberately provides no frame-injection, jamming, or evil-twin tooling. UMBRASEC publishes defense, not offense.
