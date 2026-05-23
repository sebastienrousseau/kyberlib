# `doc/audits/`

This directory holds materials prepared for **third-party security
audits** of kyberlib.

## What's here

| File | Purpose |
|------|---------|
| `RFP-v1.0.md` | Request-for-proposal template ready to send to candidate audit vendors. Covers scope, deliverables, timeline, budget. |
| `MATERIALS.md` | The audit packet — commits, test corpora, ADRs, threat model excerpt — that ships to a vendor once a contract is signed. |
| `READINESS.md` | Self-assessment checklist: things kyberlib has done so the audit isn't surprised. Maintainer fills in before sending the RFP. |
| `reports/` | Final audit reports land here, **with vendor permission** to publish. Empty until #177 closes. |

## Why this directory exists pre-audit

* **Reduces audit lead time.** When the maintainer pings a vendor,
  the materials package is ready. The vendor reads the scope, the
  threat model, and the readiness checklist in their first
  half-day — they don't bill for that time.
* **Forces alignment** between marketing claims and what the
  audit will actually look at. If the README says "FIPS 203
  conformant" and the scope doc says "audit verifies the FIPS
  203 implementation against ACVP", they say the same thing.
* **Surfaces gaps** that a 6-figure audit would otherwise discover
  on the maintainer's dime. The readiness checklist is a free
  trial run.

## Status

* **RFP draft:** ready (this commit).
* **Audit:** not yet commissioned. Tracked by
  [#177](https://github.com/sebastienrousseau/kyberlib/issues/177);
  gates v1.0.0.
* **Maintainer next step:** fill in the four `<TBD>` placeholders in
  `RFP-v1.0.md` (budget cap, target start date, name + email of
  point of contact, payment terms), then send to two or three of
  the candidate vendors listed in §7.
