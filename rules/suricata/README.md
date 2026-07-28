# Local Suricata rules

Place reviewed `.rules` files in this directory. PCAP uploads are scanned with these rules in addition to the Suricata image defaults.

`nocturneldr-payload.rules` adds review-tier signatures for the network-side
artifacts of the default msfvenom payloads commonly executed by the
NocturneLdr Windows loader. Treat every match as analyst-review input, not a
final verdict.
