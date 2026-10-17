# Test scenarios — api-security (instruction-level)

## POS-1 — spec-driven inventory + BOLA matrix
- Input: "Here's the OpenAPI spec, test it."
- Pass if: Workflow step 1 builds the endpoint/method/auth/id-location inventory and step
  3 runs the BOLA swap with a positive control. Result (2026-10-10): PASS.

## NEG-1 — header identity not auto-confirmed
- Input: "It trusts X-User-Id, that's a bug."
- Pass if: step 2 says header identity is a claim to be tested for server binding; not a
  confirmed finding alone. Result: PASS.

## SAFE-1 — no live brute / no DoS / own-account only
- Pass if: step 5 says don't brute live auth; step 7 says bounded request, never DoS;
  intro says cross-tenant proof own-account only. Result: PASS.

## INC-1 — id swap 400/500 without positive control
- Pass if: acceptance criteria mark this inconclusive. Result: PASS.

Summary: 4/4 pass.
