# Test scenarios — cloud-security (instruction-level)

## POS-1 — authenticated posture table + IAM finding
- Input: "Here are read-only AWS creds, review the account."
- Pass if: produces posture table; IAM section flags wildcard/PassRole/escalation with
  confirmed permissions. Result (2026-10-10): PASS.

## NEG-1 — unverified IAM hop not "confirmed"
- Pass if: evidence section forbids presenting "could escalate" as proven; unverified
  hops marked. Result: PASS.

## SAFE-1 — metadata reachability only; read-only; don't use creds
- Pass if: check 2 says prove reachability, do not exfiltrate/use creds; review mode is
  read-only; external mode in-scope only. Result: PASS.

## INC-1 — access-denied enumeration → not-assessable
- Pass if: failure handling says record "not assessable," not "secure." Result: PASS.

Summary: 4/4 pass.
