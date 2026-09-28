![False;Relay](banner.png)

# False;Relay

**Internet-origin pre-auth data access and forged-identity acceptance on Cisco CUCM through the Expressway MRA relay corridor**

One login. One cookie. Five requests. Your DMZ edge is now a proxy into the voice VLAN — and the call manager believes a token nobody issued.

---

## Kill Chain

| Step | Component | Description |
|------|-----------|-------------|
| 1 | **Blankhack** | The internet-facing Expressway-E checks only that the `X-Auth` cookie *exists* — all validation is deferred to the inner box |
| 2 | **Seedhack** | Expressway-C's zero-auth CDB API lets any local process plant a token record — the attacker mints their own relay credential, no MRA account needed |
| 3 | *(corridor)* | Descriptor-prefix routing (`b64url(domain/https/host/port)`) turns the relay into a client-selected proxy to internal CUCM services — proven live to :443 webapps, :8443 UDS (**200 + live XML**), :6970 TFTP-HTTP (**16,889B phone config**) |
| 4 | **Badgehack** | CUCM validates Bearer tokens by pure cluster-key crypto — no DB, no revocation, no lockout, no throttle on success. Keys extractable via published pre-auth RCE (Silent;Call / Dead;Dial). Forged `sub=administrator` token → **`JSESSIONIDSSO` issued from the internet** · `sub`-matched forge → **per-user record read + PIN write (204, DB-verified) from internet origin** |
| ★ | **Splithack** | Edge amplifiers: chunk-extension request smuggling (CVE-2026-24033/57834 class) — pre-auth, live-confirmed |
| ★ | **Wraphack** | `Content-Length: 2⁶⁴` int64 wraparound — backend-leg smuggled-request delivery demonstrated live (fix public 11 weeks before this build shipped) |
| ★ | **Namehack** | uint16 header-name truncation (CVE-2026-58155 class) — attacker-chosen values logged as legitimate TAC `TrackingID`s on both boxes |

★ = same-listener amplifiers on E:8443 (WAF-blind smuggling, forensic-correlation poisoning), not required for the corridor itself.

## Impact

The Expressway MRA corridor is how every mobile Jabber client and remote phone reaches CUCM from the internet — by design, a hole through the firewall with the voice VLAN on the other side. False;Relay turns that design hole into an authenticated-look-alike pipe: a presence-only cookie gate at the edge, a zero-auth credential plant at the inner relay, and a call manager that accepts identity from pure crypto with no database, no revocation, and no throttle behind it.

**Why this matters:**
- **Phished credential becomes full internal read** — one MRA account yields internet-origin reads of UDS service state, phone configuration files (TFTP-HTTP statics), self-care and EM endpoints — quietly, all-2xx
- **Per-user account takeover without the user's credential** — a `sub`-matched forged Bearer reads any user's record and writes its PIN/credentials from internet origin, silent, database-verified
- **Cluster-key forgery is a permanent offline identity mint** — any pre-auth CUCM RCE (two already published) extracts the signing keys: forged identity for every user, forever, with no throttle, no revocation, no audit counter — presented through the corridor from the internet
- **Zero-credential variant** — any process on Expressway-C self-mints edge credentials through the zero-auth CDB; this release ships two local root chains, so "any process" is one config bug from "root"

**Detection blind spot:** every hop on the success path returns 2xx or relayed-404 — no failed logins, no fail2ban ticks, no lockout counters touched. The traffic is product-intended shapes on product-intended lanes. The log-side tells that do exist are in [mitigations.md](mitigations.md).

## Files

| File | Description |
|------|-------------|
| [ADVISORY.md](ADVISORY.md) | Full technical advisory with request/response evidence |
| [poc.sh](poc.sh) | Proof of concept script (bash/curl) |
| [mitigations.md](mitigations.md) | Detection rules, log-side tells, hardening checklist |

## Quick Test

```bash
./poc.sh --edge edge.example.com:8443 --domain example.com \
         --target cucm01.internal.example.com --port 8443 --user MRAUSER
```

If step [2] returns `HTTP 200` with `version="15.0.1"` XML — your relay is answering internet-origin requests with internal CUCM data. If you supply `--bearer` and step [4] shows `JSESSIONIDSSO issued` — CUCM accepted a forged identity through the corridor.

## Coordination

- **Cisco PSIRT:** Notified 2026-08-04 — no response
- **ZDI:** 17 CUCM submissions pending — unprocessed
- **SSD:** Paused CUCM acquisitions
- **MITRE:** CVE IDs requested (CNA of Last Resort) — pending

Full coordination timeline: [cisco-security-research](https://github.com/0xReadingSteiner/cisco-security-research)

## Researcher

**0xReadingSteiner** — 0xReadingSteiner@proton.me

This research was conducted independently on commercially available software in a private laboratory. No proprietary source code, internal tools, or confidential information was used.

## License

Advisory text: [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). PoC script: defensive and educational purposes only.
