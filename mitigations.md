# False;Relay — Detection & Mitigation Guide for Defenders

SKYLINE-2026-004 chain (components 004–009). Companion to `ADVISORY.md`.
0xReadingSteiner — 2026-09-27

The chain's success path is **all-2xx and invisible to fail2ban/lockout telemetry**. Detection must target the traffic shape, the token-acceptance events, and the configuration state — not failed logins.

---

## 1. Network detection (Suricata ≥6, TLS-decrypting sensor in front of / beside Expressway-E :8443)

The corridor rides normal MRA HTTPS. Without TLS visibility these rules cannot fire; with it, the URI shape is highly distinctive: a ≥40-char base64url first path segment (the descriptor) followed by an internal-service path.

### 1.1 Descriptor-route abuse (corridor relay to internal services)

```
# Long b64url descriptor segment + admin/data-class internal path.
# Legitimate MRA clients hit a small, enrollment-driven set of paths under the
# descriptor lane; cucm-uds/version, headset, webdialer, axl and TFTP-HTTP
# statics from an internet client are corridor-probe signatures.
alert http $EXTERNAL_NET any -> $HOME_NET any ( \
  msg:"FALSE;RELAY descriptor-route probe to internal UDS/webapp path"; \
  flow:to_server,established; \
  http.uri; \
  pcre:"/^\/[A-Za-z0-9_\-]{40,}\/(cucm-uds|headset|webdialer|axl|ccmadmin|tomcat| informix)/Ui"; \
  classtype:attempted-recon; sid:20260041; rev:1; )

alert http $EXTERNAL_NET any -> $HOME_NET any ( \
  msg:"FALSE;RELAY descriptor-route fetch of phone config statics (TFTP-HTTP lane)"; \
  flow:to_server,established; \
  http.uri; \
  pcre:"/^\/[A-Za-z0-9_\-]{40,}\/.*\.(cnf\.xml|trustlist|tlv|loads|sbn|jar|xml\.sgn)/Ui"; \
  classtype:attempted-recon; sid:20260042; rev:1; )
```

Tune-out: your MRA deployment's *documented* client paths under the descriptor lane (edge enrollment, service discovery). Anything else under a descriptor prefix from `$EXTERNAL_NET` is worth an alert.

### 1.2 Wraphack — Content-Length ≥ 2⁶⁴ (int64 wrap desync)

```
alert http $EXTERNAL_NET any -> $HOME_NET any ( \
  msg:"WRAPHACK Content-Length 2^64-class integer (wrap desync attempt)"; \
  flow:to_server,established; \
  http.header; \
  pcre:"/Content-Length\x3a\s*\d{20,}/Hmi"; \
  classtype:protocol-command-decode; sid:20260043; rev:1; )
```

Enable Suricata's stream/decoder anomaly events (`decoder.http.invalid_chunk_size`, stream desync detection via `stream.reassembly` mismatch events) — the wrapped-CL keep-alive leak shows up as a request-line anomaly on the *next* pipelined transaction.

### 1.3 Splithack — CR/LF inside an unterminated quoted chunk-extension

Signature-level detection of chunk-extension smuggling is fragile; prefer engine-level: run Suricata with `stream.checksum-validation: yes` and alert on `HTTP2`-style double-request artifacts. A high-fidelity simple rule for the gold-test shape:

```
alert http $EXTERNAL_NET any -> $HOME_NET any ( \
  msg:"SPLITHACK chunk-extension with embedded CR/LF (smuggling gold-test shape)"; \
  flow:to_server,established; \
  http.request_body; \
  content:";a=|22|"; depth:20; \
  pcre:"/^\x3b[^\r\n]*\x22[^\x22]*\r\n/R"; \
  classtype:web-application-attack; sid:20260044; rev:1; )
```

Stronger posture: any *second* request appearing on a connection whose first request was chunked-with-extension — detect via Suricata's `flowint` on transaction count per flow if your policy treats MRA :8443 as single-transaction-per-connection (MRA clients pipeline little; alert on ≥3 tx/flow with chunked POSTs).

### 1.4 Namehack — 64KB-class header names (uint16 truncation aliasing)

```
alert http $EXTERNAL_NET any -> $HOME_NET any ( \
  msg:"NAMEHACK oversized header name (>8KB) — uint16-truncation aliasing class"; \
  flow:to_server,established; \
  http.header; \
  pcre:"/^[A-Za-z0-9\-]{8000,}\x3a/mi"; \
  classtype:bad-unknown; sid:20260045; rev:1; )
```

RFC-sane frontends reject these; the vulnerable edge accepts them. Any hit = probing. (The upstream fix rejects names > UINT16_MAX; names of 8KB+ are already far outside legitimate use.)

---

## 2. Endpoint / log detection

### 2.1 CUCM — Badgehack acceptance events (highest-value signal)

- **`JSESSIONIDSSO` issuance without an IdP authentication event.** On CUCM, correlate SSO session-cookie issuance (Tomcat access logs / SSO debug) against your IdP's auth log. A `JSESSIONIDSSO` issued to a request that never traversed the IdP = forged-token acceptance. This is the S2 signature (404/200 + `Set-Cookie: JSESSIONIDSSO` on Bearer requests).
- **Bearer requests to non-SSO webapps.** `Authorization: Bearer` arriving at `/headset`, `/cucm-uds`, `/webdialer` from the Expressway-C relay IP outside enrollment/self-care patterns.
- **`authzkeys` access audit:** any SELECT/export of the `authzkeys` table outside of upgrade/DRS operations is key-exfil (Silent;Call/Dead;Dial post-exploitation). Treat like a domain-controller `krbtgt` read.
- **UDS `/version` and statics fetches from the relay IP** at odd hours or in enumeration sequences (the corridor's recon phase — our PoC's exact footprint).

### 2.2 Expressway — corridor + seed detection

- **E network_log / C network_log correlation:** descriptor-prefix requests whose decoded destination host:port is *not* in your documented MRA service set. The descriptor is plain b64url — decode first-path-segments in your SIEM pipeline and alert on unknown internal destinations.
- **C token census:** unexpected rows in the CDB token store (planted `X-Auth` records — Seedhack). Baseline the count; any record not matching a live ECS-issued login (ECS logs `Authenticated user successfully` + TrackingID per issuance) is a plant.
- **Loopback :4370/:4372 connections on C** from non-Cisco processes (CDB zero-auth API / Erlang dist). Audit with `ss -tnp` periodically; alert on anything unexpected.
- **`TrackingID` spoofing (Namehack):** the same TrackingID value appearing across unrelated transactions, or TrackingIDs matching attacker-chosen patterns in auth-success log lines on *both* boxes.

### 2.3 Operational — ECS failed-server cache (availability trap, ADVISORY §8.6)

Symptom triad = diagnosis without pcap:
1. All MRA logins 401 (`realm="Cisco-Edge"`, `Server: CE_C ECS`) — *including known-good credentials*;
2. C's developer_log shows a boot-time `WARN ucclient ... "Request failed" ... /cucm-uds/version` from the last C restart;
3. No outbound C→CUCM:8443 traffic during login attempts (zero-dial short-circuit).

Fix: restart `edgeconfigprovisioning` on C (firestarter-managed; the supervisor relaunches it). Prevent: never reboot C while CUCM is down/being-snapshotted; verify one MRA test login after any overlapping outage.

---

## 3. Hardening checklist (priority order)

| # | Action | Blocks |
|---|---|---|
| 1 | Firewall C→CUCM to minimum ports (UDS + required webapps); **block relay path to 6970-6972** unless phones need internet-side TFTP | Corridor data breadth (Tier 1) |
| 2 | Rotate CUCM `authzkeys` after ANY suspected compromise; schedule rotation like `krbtgt` | Badgehack persistence (Tier 2) |
| 3 | Deploy §1 Suricata rules on the decrypted :8443 flow | Detection of all edge components |
| 4 | Enable §2.1 IdP-correlation alerting on CUCM | Forged-token acceptance |
| 5 | Upgrade Expressway when a rebuild lands upstream fixes `e44213f8ec` / `a9ec41a35` / `8a7a963a29`; freeze risky ATS config changes (HTTP/2, redirection, cookie ops) until then | Splithack / Wraphack / Namehack re-arming |
| 6 | Segment/monitor C management plane; alert on loopback :4370/:4372 consumers | Seedhack precondition |
| 7 | Audit X-Auth cookie domain scope + 8h lifetime vs business need; treat leaked cookies as corridor passes | Cookie-tier relay |
| 8 | Baseline CDB token census; alert on unmatched rows | Seedhack plants |

---

## 4. What does NOT work

- **fail2ban / lockouts / throttles** — the success path is all-2xx; the Bearer validator counts only failures; a valid forged token never touches a counter. (Empirically verified: full chain, zero ticks, zero bans.)
- **Rotating MRA user passwords** — the seeded-credential path (Phase A) uses no MRA credentials at all; the forged-bearer path validates by crypto, not DB.
- **The edge's own auth logging** — E logs relayed traffic as normal; C's provisioning failure paths log nothing (stdout→`/dev/console`).
- **XFF-based source restriction at CUCM** — relayed requests arrive from C's address by design; the corridor *is* the trusted path.

---

*Rules tested for syntax against Suricata 6/7 rule grammar; sids 2026004x are reserved-style placeholders — renumber for your deployment. 0xReadingSteiner — 0xReadingSteiner@proton.me*
