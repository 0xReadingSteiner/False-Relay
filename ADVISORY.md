# False;Relay — The MRA Corridor: Internet-Origin Pre-Auth Data Access and Forged-Identity Acceptance on CUCM via Expressway-E/C Relay Abuse

## 1. Advisory Information

- **Advisory ID:** SKYLINE-2026-004 (chain; components 004–009)
- **Drop Name:** False;Relay
- **Title:** Mobile and Remote Access (MRA) corridor abuse — presence-only edge authentication, seedable relay credentials, and cluster-key identity forgery combine into an internet-origin path to internal CUCM data and SSO-session acceptance
- **Components:**
  - Badgehack (SKYLINE-2026-004) — CUCM forged Bearer access-token acceptance
  - Blankhack (SKYLINE-2026-005) — Expressway-E presence-only X-Auth gate
  - Seedhack (SKYLINE-2026-006) — Expressway-C zero-auth credential seeding via CDB
  - Splithack (SKYLINE-2026-007) — chunk-extension request smuggling on the MRA edge (CVE-2026-24033 / CVE-2026-57834 class)
  - Wraphack (SKYLINE-2026-008) — Content-Length int64 wraparound with demonstrated backend-leg delivery
  - Namehack (SKYLINE-2026-009) — uint16 header-name truncation / aliasing (CVE-2026-58155 class)
- **CVSSv3.1 (chain, composed with a pre-auth CUCM RCE drop — zero credentials):** 10.0 (Critical) — `AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N` (integrity raised L→H 2026-09-28: sub-matched forged tokens proven to read AND write per-user records/credentials through the corridor — §3, §5 Phase C)
- **CVSSv3.1 (chain, standalone — one phished MRA account):** 8.5 (High) — `AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N`
- **CWE:** CWE-287, CWE-306, CWE-321, CWE-444, CWE-190, CWE-197
- **Affected Products:**
  - Cisco Expressway-E / Expressway-C X15.5.1 (Apache Traffic Server 9.2.11 Cisco rebuild, built 2026-05-08)
  - Cisco Unified Communications Manager 15.0.1.12900-234
- **Vendor:** Cisco Systems, Inc.
- **Vendor Coordination:** Cisco PSIRT unresponsive since 2026-08-04 (see §9)
- **Public Disclosure:** 2026-09-28
- **Researcher:** 0xReadingSteiner (0xReadingSteiner@proton.me)

---

## 2. Executive Summary

Cisco's Mobile and Remote Access (MRA) architecture turns Expressway-E into an internet-facing HTTPS relay (port 8443) that forwards client requests — via Expressway-C — to internal Unified Communications Manager services. This research proves, live end-to-end from the internet side of the edge, that the relay's authentication model collapses under three composable defects: **(1)** the internet-facing Expressway-E performs only a *presence* check on the `X-Auth` session cookie (Blankhack) — all cryptographic validation happens on the inner box; **(2)** the validation material lives in an Expressway-C database writable with zero authentication from any local process (Seedhack), letting an attacker with any foothold on C mint edge credentials for a cookie value of their choosing; and **(3)** CUCM accepts Bearer access tokens signed with the cluster's own `authzkeys` as full identity — no database check, no revocation, no lockout, no throttle on valid tokens (Badgehack) — and those keys are extractable through previously disclosed pre-auth RCE (Silent;Call, Dead;Dial).

The result: a request originating on the public internet reaches internal CUCM web services and is answered. We observed **HTTP 200 with live UDS XML data** through the corridor, and CUCM's SSO filter **issuing a `JSESSIONIDSSO` session cookie in response to a fully forged Bearer token** — proven twice: once via a seeded relay credential, and once via a production-faithful path using only a legitimate MRA user login. Total requests for the full chain: **five**. A 2026-09-28 follow-up fire resolved the one gate that withstood the first proof: the UDS user-resource 401 was a *self-only name-equality filter*, not an authorization decision — with a `sub`-matched forged token, the corridor delivered **full user-record reads and a credential (PIN) write accepted by the product's own database**, internet-origin, with no real credentials anywhere in the path.

---

## 3. Impact

### What an attacker can DO

**Tier 1 — one MRA account (any user, phishable), zero exploits:**
- Read CUCM service data through the corridor from the internet: UDS service endpoints (e.g. `/cucm-uds/version` returned `version="15.0.1"` and the cluster's `usersResourceAuthEnabled` policy state), the TFTP-HTTP statics surface (phone configuration files — we pulled a 16,889-byte `XMLDefault.cnf.xml` device config through the relay), UDS self-care and extension-mobility endpoints, and the CUCM PIN-change servlet. All responses 2xx; all invisible to the edge's fail2ban auth jails.
- The corridor's descriptor-prefix routing selects the internal destination: `b64url("<domain>/https/<internal-host>/<port>")` in the URL path. We demonstrated routing to CUCM:443 and CUCM:6970. The relay does not restrict which internal host:port a descriptor may name beyond the deployment's whitelist configuration.

**Tier 2 — composed with any pre-auth CUCM RCE (Silent;Call / Dead;Dial, both CVSS 10.0, both published):**
- Extract the cluster `authzkeys` signing material, forge Bearer access tokens offline for **any username** (`sub` claim — validated with `sub=administrator`), and present them through the corridor. CUCM's SSO filter accepts the forged token and issues a session cookie (`JSESSIONIDSSO`) — internet-origin identity forgery against the internal call manager, with **no database record, no failed-login counter, no lockout, and no throttle exposure** (the token validator is pure local crypto; the throttle counts only failures).
- Accepted-bearer surface observed: the SSO session issuance itself (proven live, both paths), the constraint-mapped end-user webapps, and — resolved 2026-09-28 — the UDS user-resource lane. The 401 observed on `/cucm-uds/user/<name>` during the first fire was **not** an authorization decision: `UDSFilter` enforces a single self-only rule (the authenticated name must equal the URL-path user) and there are **zero role checks** behind it. A `sub`-matched forged token (`sub=<path-user>`) returned the full user record (200), its credentials view (200), and a **PIN-reset write (204 — no old PIN required, no ownership check)**, verified after the fact in the product's Informix database (§5 Phase C). Only the mismatched-`sub` shape 401s. Practical impact: per-user account and voicemail-PIN takeover from the internet, silent, all-2xx.

**Tier 3 — any code execution on Expressway-C (any user, any process):**
- The CDB configuration API listens on C's loopback with **zero authentication**. Planting one token record (username, cookie value hash, expiry) makes an attacker-chosen `X-Auth` cookie cryptographically valid at C — no MRA credentials needed anywhere in the chain. We proved this live: a planted record opened the corridor from the internet side and carried forged-Bearer requests to CUCM (S1/S2 signature differential in §5). C also ships two independent local privilege-escalation chains to root on this release (zero-auth CDB → command injection → root; world-readable Erlang distribution cookie + `verify_none` → root), reported to the vendor separately — the "foothold on C" precondition is a *low* bar for anything already running there.

### Why the edge defenses don't stop it

- **fail2ban is blind to the success path.** The edge's 13 jails tick only on 4xx auth/intrusion classes. Every corridor request in this chain answers 2xx/404-relayed — zero ticks, zero bans, start to finish. (Empirical tick matrix, ground-truthed as root: relayed 404 = no tick; E-self 401/407 = tick; success = no tick.)
- **The upstream WAF/LB sees one clean HTTPS flow** to a legitimate service port of a legitimate product, carrying a well-formed cookie. Splithack/Wraphack (§4.4–4.5) additionally let request boundaries disagree between the edge and any stricter parser chained in front of it.
- **Forensic correlation is attacker-influenced.** The `TrackingID` header — Cisco TAC's cross-box correlation key — traverses E→C→backend and is logged verbatim on both boxes; Namehack (§4.6) even lets oversized alias headers arrive as that short name. The attacker chooses the ID stamped on their own authenticated-success entries.
- **Logging gaps compound.** Expressway-C's provisioning service sends stdout/stderr to `/dev/console`; its failure paths write nothing to the structured logs. The corridor leaves no error trail anywhere because it *is* the product's normal traffic path.

---

## 4. Technical Details

### 4.0 Architecture background

MRA deployments place Expressway-E in the DMZ (internet-facing, :8443 HTTPS) and Expressway-C inside the trusted network. Both boxes front their HTTP stacks with a Cisco rebuild of Apache Traffic Server (9.2.11 in X15.5.1). E tunnels relay traffic to C (E's `parent.config` sends domain traffic to a loopback tunnel port; the tunnel lands on **C's loopback** — C's own ATS binds 127.0.0.1:8443 and is never externally reachable). C runs the edge-config provisioning service (ECS, Python) and relays to CUCM services per the URL descriptor.

Client flows use two lane classes on E:8443:

- **Small lane** — `GET /<b64url(domain)>/get_edge_config` with HTTP Basic credentials. E relays to C's ECS, which authenticates the user against CUCM (UDS `devices` call + `clusterUser` discovery), then issues `Set-Cookie: X-Auth=<64-char token>` (8h expiry, domain-wide, HttpOnly/Secure) and returns the edge-config XML.
- **Prefix (descriptor) lanes** — `GET /<b64url("domain/https/host/port")>/<path>` with Basic auth **and** the `X-Auth` cookie. The remap chain on E applies `ts_auth` in **`check-exist`** mode; C's `ts_auth` performs the cryptographic verify: `H = sha512(b64url_decode(edgeSalt) || cookie)` must match a token record in C's CDB. On success the request is relayed to the descriptor's internal host:port.

### 4.1 Blankhack — the internet-facing edge checks existence, not validity (SKYLINE-2026-005)

E's live remap configuration (read from the running box) applies, on the catch-all relay rule: `ts_sso_flow_remap` → `ts_x_route_remap` → **`ts_auth` with `check-exist`** → `ts_whitelist_remap`. `check-exist` tests that the `X-Auth` cookie is *present and non-empty* — nothing more. All cryptographic validation is deferred to C.

Consequences:
1. The DMZ edge, the component whose entire purpose is to gate the internet, performs no credential validation on relay traffic. An unauthenticated internet attacker reaches C's validation surface and C's relay routing with one cookie header of arbitrary content (rejected at C — but *reached*, with E logging a relayed rejection rather than an edge rejection).
2. Trust is inverted: the untrusted-side box trusts; the trusted-side box verifies — over a tunnel that arrives on C's **loopback interface**, where C's own zero-auth services also live (§4.3).
3. Any weakness in C's validation data becomes an internet-reachable weakness, because E contributes no independent check to compensate.

### 4.2 The descriptor corridor

The prefix lane's destination is client-selected: the b64url descriptor in the path names protocol, internal host, and port. Demonstrated live from the internet side:

| Descriptor target | Result |
|---|---|
| `cucm01:443` (webapps) | Relay to CUCM HTTPS — S1/S2 signatures (§5) |
| `cucm01:8443` (UDS REST) | **HTTP 200 + live UDS XML** |
| `cucm01:6970` (TFTP-HTTP) | **HTTP 200, 16,889B device configuration file** |

The relay thus converts any authenticated MRA session into a general-purpose HTTP proxy into the voice VLAN — the exact network position ("a way into the LAN") the DMZ architecture exists to prevent.

### 4.3 Seedhack — zero-auth credential seeding on Expressway-C (SKYLINE-2026-006)

C's CDB configuration API (loopback TCP 4370) requires **no authentication**. Token records for the `X-Auth` scheme are CDB rows binding `{username, H = sha512(edgeSalt_bytes || cookie_value), expiry}`. Any process on C — any user, including the unprivileged service accounts — can insert a record for a cookie value the attacker chooses. From that moment:

- The attacker's chosen cookie passes C's `ts_auth` verify (we proved the planted record's hash matched and the AUTHORISER lookup returned exactly 1 record).
- E's presence-only gate (§4.1) already passes it.
- The corridor is open from the internet **without any MRA credentials existing anywhere in the chain**.

Live proof: with one planted record, internet-side requests carrying the planted cookie and a forged Bearer produced CUCM's own 401-realm signature (relay reached CUCM), then `JSESSIONIDSSO` issuance (Bearer accepted), then 200 + UDS data (§5, Phase A). The record was deleted after the test; the census returned to 0 records.

The same zero-auth CDB is the first hop of a local root chain on this release (CDB → `csvfilter` command injection → unprivileged RCE → root escalation), reported to the vendor separately — on Expressway-C, "local process" and "root" are one configuration bug apart.

### 4.4 Splithack — chunk-extension request smuggling, pre-auth on :8443 (SKYLINE-2026-007)

The shipped ATS 9.2.11 rebuild predates upstream fix `e44213f8ec` (2026-06-26) for chunked-transfer extension parsing (CVE-2026-24033 / CVE-2026-57834 class). A POST with `Transfer-Encoding: chunked` and a body beginning `1;a="<CR><LF>...` — CR/LF inside an **unterminated quoted-string chunk extension** — followed by an embedded request, is accepted; the embedded request is forwarded and served. We used Apache's own gold-test payload shape (`chunk_extension_client.py`): the live edge returned **two responses** to one send, including the embedded GET's 200 with PNG magic bytes. Patched ATS rejects this with 400 (`CHUNK_READ_ERROR`).

Cross-buffer variant confirmed: splitting the payload after `1;a="` across a 300ms network delay changes the outcome — quoted-string parser state is not preserved across reads, exactly the defect the upstream fix addresses with persistent `in_quoted_string`/`in_escape` state.

Honest scope on this deployment: embedded requests are processed as **full ATS transactions** (remap + plugin chain re-applies), so on a standalone box this is not by itself an auth bypass. Its chain value is **parser differential**: any stricter parser in front of the edge (WAF, load balancer, upstream proxy) sees body bytes where the edge sees a second request — signature and policy blindness for the hidden request, plus client-tooling invisibility.

### 4.5 Wraphack — Content-Length int64 wraparound with demonstrated backend-leg delivery (SKYLINE-2026-008)

The rebuild's `mime_parse_int64` performs no range check: `Content-Length: 18446744073709551616` (2⁶⁴) wraps to 0 mod 2⁶⁴; `2⁶⁴+1` wraps to 1 — byte-identical processing to an honest `Content-Length: 1`. Upstream fixed this in `a9ec41a35` (public since 2026-07-28, ATS 9.2.15/10.1.4); the Cisco binary was built 2026-05-08, during the embargo window — a patch-lag exposure, not a novel upstream bug.

We demonstrated the wrap **live on the internet-facing edge** as a desync oracle (keep-alive continuation leaks the next byte into a fresh request line), and demonstrated **full backend-leg delivery**: a `CL=2⁶⁴` POST carrying a body-hidden GET produced a second transaction that was remapped to a plugin-free loopback backend rule and **served (200, logged in the backend's access log with the smuggled marker in the URL)** — with an honest-CL negative control consumed as body. Smuggled requests reach backend origins that the front-door plugin chain never exposes.

### 4.6 Namehack — uint16 header-name truncation / aliasing (SKYLINE-2026-009)

CVE-2026-58155 class (upstream fix `8a7a963a29` rejects header names > UINT16_MAX; the rebuild accepts them). A header whose name is `TrackingID` + 65,536 filler bytes is stored, looked up, stripped, and serialized under the **truncated 16-bit view** — it traverses the full chain (E ATS → tunnel → C ATS → provisioning backend → response) as the real short name, proven in four independent logs plus an internet-visible response echo.

Honest scope: the strip defenses hold — client-supplied `X-Forwarded-For` and `X-Client-Cert-Info` aliases are stripped consistently; no XFF or client-certificate spoofing was achieved. What the attacker *does* get: pre-auth acceptance of 64KB alias headers (resource cost within the 128KB header limit), attacker-chosen values logged as legitimate `TrackingID` entries on **both boxes** — including on rejected transactions — poisoning the vendor's own cross-box correlation key; and a parser-differential primitive against any stricter chained frontend or raw-parsing backend.

### 4.7 Badgehack — CUCM accepts cluster-key-signed identity forgery (SKYLINE-2026-004)

CUCM 15's OAuth Bearer validation (`AuthenticationImpl.validateAccessToken`) is **pure local cryptography**: RS256 JWS verify + direct JWE decrypt of an inner claims object (`iss/sub/exp/ccid/ctyp/tid/siss/scopes`), with keys loaded at startup from the Informix `authzkeys` table (RSA private + JWE symmetric, `GetAuthzKeys`), reloaded only on DB-change events — **no key TTL, no revocation list, no per-token DB record**. The `sub` claim becomes the authenticated `user_id` verbatim; the password path is never touched. `BearerAuthenticationRequestHandler` then hardcodes the request as proxied (`isHaproxyRequest=true`) and creates the principal directly for any token whose `client_id` is not one of five hardcoded Jabber client IDs — **device-class tokens mint zero-database principals**. Rate limiting on this path counts *failed* attempts only; a valid forged token never increments any counter, and the password-lockout machinery is entirely off-path.

We resolved the full token format from product source and built an offline forge harness validated against the product's own validator as oracle: **6/6 PASS** — full-spec forge returns the chosen `user_id`; expired/tampered/bad-`siss` tokens are correctly rejected (the validator genuinely validates — the positive is not a rubber stamp); `sub=administrator` forges through; a full-fidelity token (mirroring the legitimate claim set incl. cluster `iss`) is structurally indistinguishable from product-minted output.

The keys are the trust anchor, and they are reachable: `authzkeys` is extractable by any process with CUCM root — obtainable pre-auth via Silent;Call (SKYLINE-2026-001→003) or Dead;Dial (057a/b), both published, both CVSS 10.0. Once extracted, forgery is offline, unlimited, and undetectable at the validation layer. **Live proof:** presented through the corridor from the internet side, a forged token (`sub=administrator`) caused CUCM's SSO filter to issue `JSESSIONIDSSO` — twice (§5). The token was re-minted fresh for the live fire and validated against the oracle pre-fire.

---

## 5. Proof of Concept

All results below are from live fires against the laboratory deployment (Expressway X15.5.1 + CUCM 15.0.1.12900-234), from a host on the **internet side** of Expressway-E, targeting only E's external :8443. Cookies/tokens are shown as SHA-256 prefixes only. Pace ≥3s between requests (fail2ban discipline); the entire chain ran with **zero bans and zero jail ticks on the success path**.

**TLS-verify equivalence statement (important for reproducibility):** in our lab, C's ATS ran with origin certificate verification `ENFORCED` against CUCM's self-signed certificate, which fails the C→CUCM TLS handshake (HTTP 502 at the edge). Flipping the runtime knob `proxy.config.ssl.client.verify.server.policy` to `PERMISSIVE` (hot-reloadable via `traffic_ctl`; the proxy process was never restarted) removed the 502 and the full chain executed. This 502 is a **certificate-provisioning artifact, not an authentication control**: every byte downstream of the TLS handshake is identical. A customer deployment with a properly CA-signed certificate on CUCM — the supported production configuration — is byte-for-byte in the `PERMISSIVE`-equivalent state. The chain applies to correctly provisioned production deployments *more* cleanly than to our lab.

### Phase A — seeded-credential path (no MRA credentials anywhere)

Precondition: one token record planted in C's CDB (§4.3; deleted after the test). Forge a Bearer token offline with extracted cluster keys (§4.7).

| # | Request (internet → E:8443) | Response | Meaning |
|---|---|---|---|
| A1 | `GET /<descriptor443>/headset/?x=1` + planted cookie, **no** Bearer | **401** + `WWW-Authenticate: Basic realm="Cisco Web Services Realm"` + 2,195B Cisco page + `Age: 0` | **S1** — CUCM itself answered through the corridor (relay reached the internal webapp) |
| A2 | same + `Authorization: Bearer <forged>` | **404** + `Set-Cookie: JSESSIONIDSSO=45E8…` + 2,161B | **S2** — CUCM's SSO filter **accepted the forged token** and issued an SSO session (404 = path only) |
| A3 | `GET /<descriptor8443>/cucm-uds/version` + cookie + Bearer | **200** + 319B XML: `<versionInformation … version="15.0.1"> … usersResourceAuthEnabled=false` | **Pre-auth data out of the LAN** — internet-side request, internal CUCM answered with live configuration state |

### Phase B — production-faithful path (one legitimate MRA account; nothing planted)

| # | Request | Response | Meaning |
|---|---|---|---|
| B1 | Small-lane login: `GET /<b64url(domain)>/get_edge_config` + Basic (legitimate MRA user) | **200** + 923B edge-config XML + `Set-Cookie: X-Auth=538a…` (64-char, 8h expiry, domain-wide) | Real user login issues the relay cookie |
| B2 | `GET /<descriptor8443>/cucm-uds/version` + real cookie, no Bearer | **200** + 319B UDS XML | Real cookie passes E presence-gate + C crypto-verify; relay delivers internal data |
| B3 | same + forged Bearer | **200** + 319B | Full corridor on pure real credentials |
| B4 | `GET /<descriptor443>/headset/?x=1` + real cookie + forged Bearer | **404 + `Set-Cookie: JSESSIONIDSSO=ABDA…`** + 2,161B | **S2 with the real cookie** — forged identity accepted from the internet |
| B5 | `GET /<descriptor8443>/cucm-uds/user/<mrauser>` + cookie + Bearer | **401** (2,143B, session cookies set, no `WWW-Authenticate`) | Observed as fired (`sub=administrator` ≠ path user). **Resolved 2026-09-28 — Phase C below:** the 401 is `UDSFilter`'s self-only name-equality rule, not an authorization decision. |

The S1/S2 differential (401+realm vs 404+`JSESSIONIDSSO`, stable byte-length signatures) is a reliable oracle for "forged token accepted" without touching any data.

### Phase C — UDS gate resolution (2026-09-28; seeded path, `sub`-matched forge, zero real credentials)

The B5 401 was traced in product code to `UDSFilter` (cucm-uds.war): the filter's entire logic is *authenticated name must EQUAL the URL-path user*; no `isUserInRole` check exists anywhere in the war. Re-fired with a forged token whose `sub` matches the path user (planted relay credential; keys unchanged epoch; ≥5s pacing; zero fail2ban ticks — relayed-401 class verified no-tick):

| # | Request (internet → E:8443 → corridor → CUCM) | Response | Meaning |
|---|---|---|---|
| C1 | `GET /<descriptor8443>/cucm-uds/version` | **200** 319B | corridor + valve sanity |
| C2 | `GET /<descriptor8443>/cucm-uds/user/<mrauser>` (sub-matched Bearer) | **200** 1,640B — full user record (identity, locale, home cluster, device/credential/extension/speed-dial links) | **B5 flipped 401→200 by `sub`-match alone** |
| C3 | `GET /<descriptor8443>/cucm-uds/private/user/<mrauser>` | **200** 1,688B | private lane delivers |
| C4 | `GET /<descriptor8443>/cucm-uds/user/<mrauser>/credentials` | **200** 451B login-details view | the allowlist's `?` path matcher covers multi-segment subpaths |
| C5 | `PUT /<descriptor8443>/cucm-uds/user/<mrauser>/credentials` (`<credential type="pin">…`) | **204 No Content** | **PIN write accepted — no old PIN, no ownership check** |

Write verified database-side: the Informix credential row's `timechanged` equals the C5 fire instant (hash-only evidence discipline; the PIN value is never logged). The corridor allowlist carries `GET,PUT,DELETE /cucm-uds/user/?` verbatim — the write lane is product-intended traffic. A Jabber-`client_id` forge variant additionally reaches the DB-backed SSO realm path (session issuance confirmed; principal-class discrimination documented in the run record). Voicemail push (Unity, using the server's stored credentials on `currentCred=NULL` PIN resets) is code-proven only — no Unity server in the lab. All teardown verified: planted record deleted (census 0), knobs restored, no service restarts beyond the documented ECS fix.

### poc.sh

`poc.sh` in this repository executes the **non-destructive, credential-tier** demonstration (B1→B2→B4-differential): small-lane login with a legitimate MRA account, descriptor relay probe, and the S1/S2 Bearer differential when a forged token file is supplied. GET requests only; ≥3s pacing; secrets hashed in output; nothing persisted. Token forging itself is **not** included — it requires cluster keys obtainable only through the separately published RCE chains, and publishing a forge tool is out of scope by design.

```bash
./poc.sh --edge edge.example.com:8443 \
         --domain example.com \
         --target cucm01.internal.example.com --port 8443 \
         --user <MRA_USERNAME>
# password prompted (never argv); add --bearer token.txt for the S1/S2 differential
```

Expected output (vulnerable deployment):

```
[1] small-lane login ............ HTTP 200, X-Auth len=64 sha8=xxxxxxxx  ← relay cookie issued
[2] corridor /cucm-uds/version .. HTTP 200, 319B XML, version="15.0.1"  ← internal data, internet-origin
[3] S1 control (no bearer) ...... HTTP 401 + realm="Cisco Web Services Realm"  ← relay reached CUCM
[4] S2 forge differential ....... HTTP 404 + Set-Cookie: JSESSIONIDSSO=…  ← FORGED IDENTITY ACCEPTED
[!] VULNERABLE — False;Relay corridor live end-to-end
```

---

## 6. Root Cause Analysis

1. **Trust inversion at the edge (Blankhack).** The MRA design places credential *validation* on the inner box and credential *existence-checking* on the internet-facing box. The DMZ component contributes no independent security decision; every validation-data weakness on C is automatically internet-reachable.
2. **Validation data in a zero-auth store (Seedhack).** The relay's trust anchors (edge salt, token records) live in a configuration database whose loopback API authenticates nobody. The product's own local privilege-escalation surface (two independent root chains on this release) makes "any local process" a realistic attacker position — and the appliance's security model otherwise assumes no untrusted local code ever runs.
3. **Bearer tokens as pure crypto, identity as a claim (Badgehack).** CUCM's token validation deliberately avoids the database (performance), so a token signed by a cluster key *is* an identity — any `sub`, no issuance record, no revocation, no audience/path binding (a token minted for SSO flows is equally valid presented to any Bearer-accepting webapp), and no throttle on success. Key confidentiality is the entire security boundary, in a product with published pre-auth root chains.
4. **A proxy fork frozen inside an embargo window (Splithack/Wraphack/Namehack).** The May-2026 ATS 9.2.11 rebuild shipped without ≥3 upstream fixes already public at build time (one fixed 11 weeks before, one 4 weeks before). The fork lags upstream ~4 releases / ~100 CVEs; today's unreachability of several classes is *configuration-dependent* (HTTP/2 off, no redirection, no cookie ops) — one config change re-arms whole classes with zero exploit work.
5. **Design-level: the corridor is the product's normal path.** Nothing in the chain is anomalous traffic. The relay, the cookie, the descriptor routing, the Bearer header — every element is MRA working as documented. The failure is that the composition of individually reasonable mechanisms yields an internet-origin proxy into the voice VLAN whose success path is invisible to the product's own abuse defenses (fail2ban, throttles, audit counters).

---

## 7. Affected Components

| Component | Version / Build | Role in chain |
|---|---|---|
| Cisco Expressway-E | X15.5.1 (`oak_v15.5.1_rc_2`), ATS 9.2.11 Cisco rebuild #050801 (2026-05-08, commit `e86c30a2d4ee`) | Blankhack gate; Splithack/Wraphack/Namehack surface (:8443 pre-auth) |
| Cisco Expressway-C | X15.5.1 (same build) | Seedhack (CDB :4370 zero-auth); `ts_auth` verify; relay to CUCM |
| Cisco Unified Communications Manager | 15.0.1.12900-234 | Badgehack (Bearer validation, `authzkeys`); corridor endpoints (UDS, TFTP-HTTP :6970, webapps :443) |

Earlier X14.x/X15.x releases share the MRA relay architecture and the same ATS lineage; the X14.3.7 SIP-parser defects published as Blind;Wire confirm the fork's patch-lag pattern predates X15.5.1. Exact per-version exposure of components 004–006 was not tested and is stated as likely, not proven.

---

## 8. Remediation

**No vendor patch exists for components 004–006 at publication.** Defenders should act now:

1. **Assume corridor exposure for every MRA deployment.** Audit what your descriptor lanes can reach: firewall Expressway-C → CUCM to the *minimum* service/port set (UDS + the specific webapps MRA needs). Block C → CUCM:6970-6972 (TFTP-HTTP statics) from the relay path unless phones genuinely require internet-side TFTP — the all-paths statics lane is the widest data exposure we observed.
2. **Treat `authzkeys` as crown-jewel key material.** Any suspected CUCM compromise (either published pre-auth RCE chain, any admin-credential leak) must trigger cluster key rotation — validation is event-driven, so rotation invalidates forged tokens immediately. Until rotated, a single key extraction yields permanent, throttle-free, lockout-free identity forgery for every user.
3. **Monitor the success path, not the failure path.** fail2ban/lockout telemetry is structurally blind to this chain. Alert on: internet-origin requests to descriptor-prefix routes whose paths target admin-class or statics services; `JSESSIONIDSSO` issuance on CUCM without a corresponding SSO IdP authentication event; UDS `/version` and TFTP-HTTP fetches sourced from the Expressway-C relay IP at non-enrollment times; and **UDS `PUT /cucm-uds/user/<name>/credentials` (PIN resets) arriving via the relay path** — silent per-user credential takeover is the chain's highest-integrity outcome (§5 Phase C). Detection rules: `mitigations.md`.
4. **Patch/upgrade the ATS layer** when Cisco ships a rebuild containing upstream fixes `e44213f8ec` (chunk-extension state), `a9ec41a35` (CL int64 range check), `8a7a963a29` (header-name length) — and treat config changes (enabling HTTP/2, redirection, cookie rewriting) as re-arming dormant CVE classes on the current fork.
5. **Restrict Expressway-C loopback trust.** The zero-auth CDB API and the two local root chains mean any foothold on C equals full relay-credential minting. Segment management-plane access to C aggressively; monitor for unexpected processes on C's loopback :4370/:4372.
6. **Operational (availability) note — ECS failed-server cache:** if Expressway-C restarts while CUCM is briefly unreachable (maintenance, snapshot, network blip), C's provisioning service caches CUCM as *failed* and answers **every** subsequent MRA login with 401 **without ever contacting CUCM** — indefinitely (observed ≥14.5h; the internal retry timer never healed it), symptom-identical to wrong-password, with nothing logged. We discovered this live: valid credentials 401'd with **zero outbound packets** during login attempts (pcap-proven). Fix: restart the `edgeconfigprovisioning` service after any CUCM outage that overlapped a C boot. Helpdesks chasing "user password problems" during such an outage are being misdirected by this cache.
7. **X-Auth cookie scope audit:** the issued cookie is domain-wide with an 8-hour lifetime; review whether your deployment needs that breadth, and treat any leaked cookie as an 8-hour corridor pass.

---

## 9. Vendor Coordination Timeline

| Date | Action |
|---|---|
| 2026-08-04 | Cisco PSIRT contacted (CUCM pre-auth root chain, Silent;Call). No response to date. |
| 2026-08-04 | MITRE CNA-of-Last-Resort CVE request (3 vulns). Pending to date. |
| 2026-08-10 | Cisco PSIRT contacted (Expressway Blind;Wire). No response to date. MITRE request for 056. Pending. |
| 2026-06 → 2026-09 | MRA corridor research: edge remap/plugin chain mapped; carrier access model resolved (Basic + X-Auth per lane); ATS CVE corpus adjudicated (38/38); chunk-extension smuggling and CL-wrap backend-leg delivery demonstrated live; CUCM Bearer token format fully resolved from product code; offline forge harness 6/6 against the product validator oracle. |
| 2026-09-27 | **Chain fired live end-to-end, both paths** (seeded-credential and production-faithful). Full teardown verified (planted record deleted — census 0; runtime knobs restored; no service restarts beyond the documented ECS fix; secrets shredded). |
| 2026-09-28 | **The one gate that withstood the first fire is resolved live:** the UDS user-resource 401 was a self-only name-equality filter (`UDSFilter`), not authorization — zero role checks behind it. Sub-matched forged Bearer delivered full user-record reads and a credential (PIN) write (204) from internet origin, verified in the product's Informix database. Composed-chain integrity raised I:L→I:H; composed CVSS re-rated **10.0** (`S:C/C:H/I:H/A:N`). Teardown verified. |
| 2026-09-27 | Components 004–006 prepared for Cisco PSIRT submission; 007–009 reference existing upstream CVE classes with product-specific live confirmation. |
| 2026-09-28 | **Drop 04 published** — False;Relay repository public (SKYLINE-2026-004→009). Fourth drop published without vendor acknowledgment. |

Seventeen prior ZDI submissions remain unprocessed; SSD paused CUCM acquisitions stating Cisco will not address existing reports. This is the fourth drop published without any vendor acknowledgment.

---

## 10. Disclosure Statement

This research was conducted independently on commercially available software in a private laboratory, without proprietary source-code access, internal tools, or confidential vendor information. All live testing occurred against lab-owned equipment under explicit owner authorization; test credentials were supplied by the lab owner; no third-party systems were touched. Every claim in this advisory is backed by wire-level evidence (request/response signatures, packet captures, byte-code and binary analysis, product-code cross-validation). Where a primitive fell short of full exploitation (B5, §5), the limit is published exactly as observed. Secrets (session cookies, tokens, keys, credentials) are referenced by SHA-256 prefix only; no secret material appears in this advisory or the PoC.

Given Cisco's documented non-engagement across four channels (ZDI ×17, SSD, PSIRT ×2, MITRE pending since 2026-08-04), publication proceeds so that defenders can detect and mitigate exposure now.

---

## 11. References

- Cisco Expressway Series: https://www.cisco.com/c/en/us/products/unified-communications/expressway-series/index.html
- Cisco Unified Communications Manager: https://www.cisco.com/c/en/us/products/unified-communications/unified-communications-manager-callmanager/index.html
- Cisco MRA Deployment Guide: https://www.cisco.com/c/en/us/support/unified-communications/expressway-series/products-deployment-guides-list.html
- Apache Traffic Server (upstream fixes `e44213f8ec`, `a9ec41a35`, `8a7a963a29`): https://github.com/apache/trafficserver
- CWE-287: https://cwe.mitre.org/data/definitions/287.html · CWE-306: https://cwe.mitre.org/data/definitions/306.html · CWE-321: https://cwe.mitre.org/data/definitions/321.html · CWE-444: https://cwe.mitre.org/data/definitions/444.html · CWE-190: https://cwe.mitre.org/data/definitions/190.html
- Related drops: [Silent;Call](https://github.com/0xReadingSteiner/Silent-Call) (SKYLINE-2026-001→003) · [Blind;Wire](https://github.com/0xReadingSteiner/Blind-Wire) (056) · [Dead;Dial](https://github.com/0xReadingSteiner/Dead-Dial) (057a/b)
- Master index: [cisco-security-research](https://github.com/0xReadingSteiner/cisco-security-research)

---

*0xReadingSteiner — PGP D5E22255F645A8B935056C278C0958C5D533080A — 0xReadingSteiner@proton.me*

---

## Related Vendor Advisories — Distinct From This Work

Pre-checked 2026-09-29 against Cisco's publication record. No Cisco advisory covers any component of this drop; the two nearest prior advisories are different mechanisms on different surfaces, cited here so reviewers can verify the boundary themselves:

- **CVE-2024-20497** ([cisco-sa-expressway-auth-kdFrcZ2j](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-expressway-auth-kdFrcZ2j), fixed 15.2, Sep 2024): inadequate authorization checks letting a **logged-in** MRA user on a **clustered Expressway-E with OAuth** impersonate other users (call capture, caller-ID spoofing). **Distinct from Blankhack:** the presence-only `X-Auth` cookie gate documented here is an absence of edge validation entirely (not weak inter-user authorization), was proven live on **X15.5.1 — three minor releases after Cisco's 15.2 fix** — and enables unauthenticated corridor relay rather than cross-user impersonation within an authenticated session. Its survival on post-fix releases is itself the evidence of a separate root cause.
- **CVE-2024-20253** ([cisco-sa-voice-rce-mORhqY4b](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-voice-rce-mORhqY4b), Jan 2024): unauthenticated **CUCM/Unity** Collaboration Database web-API access chained to SSRF and root. **Distinct from Seedhack:** Seedhack targets the **Expressway-C** collaboration-database loopback service (TCP :4370, zero authentication, relay-credential planting) — a different product component than the CUCM/Unity CDB web API of CVE-2024-20253. No Cisco advisory addresses the Expressway CDB loopback service.
- **Upstream Apache Traffic Server classes** (CVE-2026-24033 / CVE-2026-57834 chunk-extension smuggling; int64 Content-Length wrap fix `a9ec41a35`; CVE-2026-58155 header-name truncation) are cited per-component as upstream classes with public fixes predating or embargo-overlapping the shipped Cisco rebuild. **No Cisco product advisory exists for the Expressway ATS rebuild** — the most recent Expressway-specific PSIRT advisory remains [CVE-2025-20179](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-expressway-xss-uexUZrEW) (XSS, Feb 2025).
