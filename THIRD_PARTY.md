# Third-party components and detection content

C2 Signal does not vendor the optional community rule repositories. `scripts/fetch-rules.sh` downloads pinned revisions into the ignored `rulesets/` directory. Each repository remains governed by its own license and attribution requirements.

| Content | Upstream | Pinned revision |
|---|---|---|
| Yara-Rules | https://github.com/Yara-Rules/rules | `0f93570194a80d2f2032869055808b0ddcdfb360` |
| Elastic protections artifacts | https://github.com/elastic/protections-artifacts | `9a00306e5cccfb553949aae393a5cacfdedbda4c` |
| Te-k Cobalt Strike YARA | https://github.com/Te-k/cobaltstrike | `9ac4d5d931b6228a8b17dbcb336ad915acf7d41f` |
| Detect It Easy YARA | https://github.com/horsicq/Detect-It-Easy | `3aa0b315a6e71946f5ca5cc9f8d1335b026d61c4` |
| SigmaHQ rules | https://github.com/SigmaHQ/sigma | `941c27449146f1afb95f2ea36b2b4528d988dfbe` |

Runtime engines are built or installed from their upstream projects and distributions:

- Chainsaw 2.16.0: https://github.com/WithSecureLabs/chainsaw
- Suricata 8.0.5: https://suricata.io
- YARA: https://virustotal.github.io/yara/

The bundled Source Han Sans SC webfont subset is derived from Adobe Source Han Sans 2.005R. Its license is included at `frontend/public/fonts/LICENSE.txt`.

Before publishing a release, review every upstream license again and update pinned revisions and this file together.
