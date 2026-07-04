# Local YARA rules

Place organization-specific `.yar` or `.yara` files in this directory. They are mounted read-only at `/rules/yara/local`.

`cobalt_strike_beacon.yar` adds reviewed triage rules for decoded Beacon
configuration blocks, Beacon Object File API imports, and core Beacon PE
artifacts. Treat every match as an analyst-review signal rather than a final
malicious verdict.
