---
name: patch-krack-fragattacks
description: "Patch-and-exposure verification for KRACK (WPA2 4-way-handshake key reinstallation, CVE-2017-13077 to CVE-2017-13088 excluding 13083 and 13085, VU#228519) and FragAttacks (Wi-Fi fragmentation and aggregation flaws, CVE-2020-24586/24587/24588, CVE-2020-26139 to CVE-2020-26147), where an in-range attacker decrypts, replays, and injects Wi-Fi frames (MITRE ATT&CK T1557, T1040). Covers fixed client, driver, access-point, and supplicant versions, weak host signals from Windows WLAN-AutoConfig and wpa_supplicant, Microsoft Defender Vulnerability Management fleet exposure queries, the WIDS/WIPS nonce-reuse signal as the only true detection, and patch, segmentation, and encrypted-tunnel hardening. Use when verifying laptops, phones, access points, or IoT are patched against KRACK or FragAttacks, auditing Wi-Fi firmware and driver exposure, hunting unpatchable wireless devices, or triaging a WIPS key-reinstallation or EAPOL-replay alert."
---

# KRACK and FragAttacks - Patch and Exposure Verification

> **Tier 2 - methodology skill.** No bespoke UMBRASEC detection rule ships with this skill yet. It gives the defender's method, the log sources and signals, the hunt, and the hardening, and points to public, maintained rule sources by URL. Promotion to Tier 1 (a sourced, tuned UMBRASEC rule) is tracked in [COVERAGE.md](https://github.com/umbrasec-labs/umbra-blue/blob/main/COVERAGE.md). Do not treat the content below as citing a UMBRASEC rule; there is none for this threat yet.

## TL;DR

KRACK and FragAttacks are radio-layer attacks against the Wi-Fi link, so you cannot usefully detect them from host or SIEM logs the way you would a credential attack. Treat them as a patch-and-exposure problem. The whole defensible surface is version state: every Wi-Fi client (OS plus wireless driver), every access point and wireless controller, and every embedded or IoT radio must be past the vendor fix. KRACK was fixed on clients and APs in late 2017 (Microsoft addressed the group-key variant CVE-2017-13080 in the October 2017 updates; the reference `wpa_supplicant`/`hostapd` patches landed the same month). FragAttacks fixes shipped across 2021 and are rolled into `wpa_supplicant`/`hostapd` 2.10. The three things that actually reduce risk, in order: patch everything that can be patched, wrap all traffic in encrypted tunnels (VPN and TLS) so a decrypted frame yields nothing, and segment the devices that will never be patched. Note two honesty points up front: 802.11w Management Frame Protection does not fix KRACK, and WPA3 does not fix the FragAttacks design flaws.

## What it looks like, defender view

Both attacks require the adversary to be in radio range and to sit between a client and its access point on the wireless link. In KRACK the attacker forces a retransmission of message 3 of the WPA2 4-way handshake so the victim reinstalls a key that is already in use, resetting the nonce and replay counters and letting the attacker decrypt, replay, and in some modes forge frames. In FragAttacks the attacker abuses how frames are fragmented and how A-MSDU aggregation is parsed, mixing fragments encrypted under different keys or smuggling plaintext frames, to inject traffic or exfiltrate data. From a defender's seat almost none of this appears in telemetry: it happens below the IP layer and leaves no authentication failure, no lockout, and no process event. The only host-side shadow is churn on the wireless association (unexpected disconnect and reconnect cycles on a single SSID), and the only true signal is a WIDS/WIPS sensor observing nonce reuse or a replayed EAPOL-Key message 3 over the air.

## Log sources and signals

- **Windows client association churn.** `Microsoft-Windows-WLAN-AutoConfig/Operational` carries Event ID 8001 (successful connect), 8002 (connect failure), and 8003 (disconnect, with a reason code). A handshake-manipulation attack can show up as an abnormal 8003-then-8001 reconnect cycle on one SSID and adapter. This is a weak, high-noise signal (roaming, poor signal, and driver resets look identical), so use it only as corroboration, never as a primary alert.
- **Linux supplicant logs.** `wpa_supplicant` writes to syslog/journald: watch for `WPA: Key negotiation completed`, repeated `CTRL-EVENT-DISCONNECTED reason=` lines, and 4-way-handshake retries on a stable link. For exposure, `wpa_supplicant -v` and `hostapd -v` report the version you must compare against the fix baseline.
- **Exposure at fleet scale (Microsoft Defender Vulnerability Management).** The advanced-hunting tables are the real verification surface. Query `DeviceTvmSoftwareVulnerabilities` filtered on the KRACK and FragAttacks `CveId` list (fields `DeviceId`, `DeviceName`, `CveId`, `SoftwareName`, `SoftwareVersion`), and join `DeviceTvmSoftwareInventory` to confirm the installed wireless driver and OS build. This answers "which devices are still exposed" directly from the CVE identifiers.
- **Windows patch and driver state on the host.** `Get-HotFix` (or the `DeviceTvmSoftwareInventory` KB data) confirms the OS cumulative update level, and `Get-NetAdapter | Format-List Name, DriverVersion, DriverDate` plus the adapter properties under the network class registry key confirm the wireless driver version, which is where many client-side KRACK and FragAttacks fixes live.
- **Access point and controller inventory.** Cisco WLC/Catalyst, Aruba (ArubaOS and Central), Meraki, Ubiquiti, and Mikrotik all expose a firmware version through their management plane and syslog. The AP is the other half of the patch: FragAttacks in particular need both ends fixed.
- **WIDS/WIPS alerts.** A monitoring-mode sensor is the only component that can see the attack on the air. Its alert classes for key reinstallation, nonce reuse, EAPOL-Key replay, and fragmented-frame anomalies are the true detection signal. These require dedicated monitor radios and still produce false positives from flaky clients, so treat an alert as a prompt to investigate radio-range presence, not as proof.

## Detection approach

Lead with exposure verification, not alerting. Enumerate every Wi-Fi-capable asset, resolve each one's OS build, wireless driver version, AP/controller firmware, and supplicant version, and compare against the KRACK and FragAttacks fix baselines so the output is a ranked list of still-exposed devices. The authoritative per-device checks are vulnerability-scanner plugin families (Tenable/Nessus and Qualys both publish KRACK and FragAttacks detections keyed to the CVE lists) and Microsoft Defender Vulnerability Management querying the same CVEs. Point true over-the-air detection at your WIDS/WIPS: enable and tune its key-reinstallation, nonce-reuse, and EAPOL-replay signatures, which belong to the wireless vendor's analytic set rather than to host-log SIEM content.

Be plain about the rule situation. SigmaHQ (https://github.com/SigmaHQ/sigma) has no dedicated rule for a radio-layer attack like this, because the attack produces no reliable host-log event to match; the WLAN-AutoConfig churn above is too noisy to encode as a shipped rule, and no tuned UMBRASEC rule exists for this threat yet. The honest detection posture is: verify patch state with a scanner, watch exposure with Defender Vulnerability Management, and rely on WIPS for the air-side signal.

## Threat hunt

Hypothesis: one or more Wi-Fi devices on the estate are still exposed to KRACK or FragAttacks and should be patched, isolated, or retired.

1. Build the inventory. Enumerate every device with a Wi-Fi radio: managed laptops and phones, access points and controllers, printers, cameras, and IoT. For each, record OS build, wireless driver version, AP/controller firmware, and `wpa_supplicant`/`hostapd` version where applicable.
2. Resolve exposure by CVE. In Defender advanced hunting, run `DeviceTvmSoftwareVulnerabilities` filtered to the KRACK CVEs (CVE-2017-13077, 13078, 13079, 13080, 13081, 13082, 13084, 13086, 13087, and 13088; note that 13083 and 13085 are not part of the KRACK set) and the FragAttacks CVEs (CVE-2020-24586, CVE-2020-24587, CVE-2020-24588, and CVE-2020-26139 through CVE-2020-26147), and corroborate with a Tenable or Qualys scan using their KRACK and FragAttacks plugin families.
3. Confirm both ends. For each wireless segment, verify the AP/controller firmware is past the vendor fix, not only the clients; a patched laptop on an unpatched AP is still exposed to the FragAttacks design flaws.
4. Flag the unpatchable. Identify EOL IoT and embedded radios that will never receive a fix. These are the residual risk: route them to a segmentation and encrypted-tunnel decision rather than leaving them on the trusted SSID.
5. Review the air-side history. Pull your WIDS/WIPS key-reinstallation, nonce-reuse, and EAPOL-replay alerts over a long window and correlate any hits with the physical location and timing, since the attacker must have been in radio range.

## Hardening

The controls below are ranked by how much they actually reduce risk. Only the two that ground cleanly in the UMBRASEC [foundation guide](https://umbrasec.dev/guide/foundation.html) framework table appear in the table; the compensating controls that do not map to a guide cell are kept as prose.

| Control | Essential Eight | ISO 27001:2022 | NIST CSF 2.0 |
|---|---|---|---|
| Patch client OS, wireless drivers, AP and controller firmware, and the supplicant past the KRACK and FragAttacks fix baselines | Patch applications; Patch operating systems | A.8.8 Technical vulnerabilities | ID.RA; PR.PS Platform Security |
| Maintain an inventory of every Wi-Fi radio so exposure can be bounded and tracked | Assumed prerequisite | A.5.9 Inventory of assets | ID.AM Asset Management |

Compensating controls (prose, no clean guide mapping):

- **Encrypted tunnels end to end.** Assume the Wi-Fi link can be decrypted and make that worthless: enforce TLS for all application traffic and a VPN for anything sensitive, so a frame the attacker recovers is already ciphertext. This is the most robust mitigation and the only one that protects the devices you cannot patch (MITRE D3FEND D3-ET Encrypted Tunnels).
- **Segment and isolate the unpatchable.** Put EOL IoT and embedded radios on a separate, firewalled SSID/VLAN with no path to crown-jewel systems, so a link-layer compromise of one is contained.
- **Management Frame Protection (802.11w) and WPA3, with correct expectations.** Enable PMF and move to WPA3-SAE for their broader benefits, but do not treat either as a fix: 802.11w does not stop KRACK, and WPA3 does not close the FragAttacks aggregation, mixed-key, and fragment-cache design flaws. Both still require the client and AP patches.

## Honest limitations

This is an exposure-verification skill, not a detection skill, because the attack offers almost nothing to detect from host or SIEM telemetry. The WLAN-AutoConfig and supplicant churn signals are too noisy to alert on reliably, and true over-the-air detection depends on WIDS/WIPS monitor radios you may not have deployed everywhere. Patch verification is only as complete as the asset inventory, so shadow IoT, personal phones, and BYOD escape it. FragAttacks mixes implementation bugs with protocol design flaws, and both the client and the access point must be patched for the design-flaw fixes to hold; EOL devices that will never be patched leave residual risk that only segmentation and encrypted tunnels contain. The one scope limiter in the defender's favor is physical: the attacker must be within radio range of the target, which bounds where and when these attacks can happen.

## ATT&CK and D3FEND

- MITRE ATT&CK: [T1557 Adversary-in-the-Middle](https://attack.mitre.org/techniques/T1557/) (the link-layer decrypt/replay/inject position both attacks establish) and [T1040 Network Sniffing](https://attack.mitre.org/techniques/T1040/) (the passive frame recovery KRACK enables).
- MITRE D3FEND: [D3-SU Software Update](https://d3fend.mitre.org/technique/d3f:SoftwareUpdate/) is the primary countermeasure for a patch-and-exposure skill; [D3-ET Encrypted Tunnels](https://d3fend.mitre.org/technique/d3f:EncryptedTunnels/) is the compensating control that defangs link-layer decryption.
- Primary sources: KRACK CVE-2017-13077 to CVE-2017-13088 (excluding 13083 and 13085) and CERT/CC VU#228519 (https://www.kb.cert.org/vuls/id/228519); FragAttacks CVE-2020-24586/24587/24588 and CVE-2020-26139 through CVE-2020-26147; the researcher advisories at https://www.krackattacks.com/ and https://www.fragattacks.com/.
- Public verification sources: Microsoft Defender Vulnerability Management (`DeviceTvmSoftwareVulnerabilities`, `DeviceTvmSoftwareInventory`), Tenable/Nessus and Qualys KRACK and FragAttacks plugin families, and the `wpa_supplicant`/`hostapd` 2.10 release notes. SigmaHQ (https://github.com/SigmaHQ/sigma) ships no dedicated rule for this radio-layer threat.

**Scope note.** This is a defensive skill: it explains KRACK and FragAttacks only as far as patch verification, exposure assessment, and mitigation require, and it ships no offensive wireless tooling, attack scripts, or exploitation instructions.
