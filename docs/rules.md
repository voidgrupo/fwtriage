# Rules

Generated from the catalog in `src/fwtriage/model/rules.py` by `./check docs`. Do not edit
by hand: the guard `rules-doc-fresh` fails when this file and the catalog disagree.

Severity is the default; an analyzer may lower it with the reason in the finding. See
[`docs/architecture/analyzers.md`](./architecture/analyzers.md) for severity and confidence.

| Rule | Title | Default severity | Reference |
|---|---|---|---|
| `FWT-ACC-001` | Login account without a password | high | [CWE-258](https://cwe.mitre.org/data/definitions/258.html) |
| `FWT-ACC-002` | Password hash in a weak scheme | high | [CWE-916](https://cwe.mitre.org/data/definitions/916.html) |
| `FWT-ACC-003` | Password hash fixed in the image | medium | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) |
| `FWT-ACC-004` | Account other than root with UID 0 | high | — |
| `FWT-SEC-001` | Private key embedded in the image | critical | [CWE-321](https://cwe.mitre.org/data/definitions/321.html) |
| `FWT-SEC-002` | Encrypted private key embedded in the image | medium | [CWE-321](https://cwe.mitre.org/data/definitions/321.html) |
| `FWT-SEC-003` | Cloud access key embedded in the image | critical | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) |
| `FWT-SEC-004` | Wi-Fi passphrase in configuration | high | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) |
| `FWT-SEC-005` | Factory SSH authorized key | high | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) |
| `FWT-SVC-001` | Shell on a console without login | medium | [CWE-306](https://cwe.mitre.org/data/definitions/306.html) |
| `FWT-SVC-002` | Telnet started at boot | high | [CWE-319](https://cwe.mitre.org/data/definitions/319.html) |
| `FWT-SVC-003` | Cleartext service present | low | [CWE-319](https://cwe.mitre.org/data/definitions/319.html) |
| `FWT-SVC-004` | Network services started at boot | info | — |
| `FWT-SVC-005` | Telnet gives a shell without login | critical | [CWE-306](https://cwe.mitre.org/data/definitions/306.html) |
| `FWT-SVC-006` | SSH accepts empty passwords | high | [CWE-258](https://cwe.mitre.org/data/definitions/258.html) |
| `FWT-HRD-001` | Executables without stack protector | low | [CWE-693](https://cwe.mitre.org/data/definitions/693.html) |
| `FWT-HRD-002` | Executables with executable stack | medium | [CWE-693](https://cwe.mitre.org/data/definitions/693.html) |
| `FWT-HRD-003` | Executables without position independence | low | [CWE-693](https://cwe.mitre.org/data/definitions/693.html) |
| `FWT-HRD-004` | Executables without full RELRO | low | [CWE-693](https://cwe.mitre.org/data/definitions/693.html) |
| `FWT-VUL-001` | Component with known vulnerabilities | medium | [CWE-1395](https://cwe.mitre.org/data/definitions/1395.html) |
| `FWT-IMG-001` | Unidentified high-entropy region | info | — |
| `FWT-IMG-002` | Container checksum mismatch | low | — |
| `FWT-SIG-001` | Firmware image is not signed | medium | [CWE-347](https://cwe.mitre.org/data/definitions/347.html) |
| `FWT-SIG-002` | Weak signature algorithm or key | high | [CWE-327](https://cwe.mitre.org/data/definitions/327.html) |
| `FWT-SIG-003` | FIT signs images, not configurations | medium | [CWE-347](https://cwe.mitre.org/data/definitions/347.html) |
| `FWT-SIG-004` | Signed configuration leaves images unsigned | medium | [CWE-347](https://cwe.mitre.org/data/definitions/347.html) |
| `FWT-SIG-005` | Bootloader verification key is not required | medium | [CWE-347](https://cwe.mitre.org/data/definitions/347.html) |
