# Vulnerable mobile samples — workshop demo inputs

This directory holds **deliberately vulnerable** mobile artifacts used by the
DevSecOps pipeline demo (see `.github/workflows/pr-security-gate.yml`).

## What's here

| File                  | Source                                                        | Vulnerabilities                                           |
| --------------------- | ------------------------------------------------------------- | --------------------------------------------------------- |
| `InsecureBankv2.apk`  | https://github.com/dineshshetty/Android-InsecureBankv2        | Hardcoded creds, weak crypto, insecure storage, exported components, broken auth, insecure WebView, ... |

## Why an APK is committed instead of source

The pipeline's **DAST job** uses MobSF, which gives much richer findings when
given a packaged binary (manifest analysis, permissions audit, signing-cert
inspection, library-version detection) than when given raw source.

For the workshop demo, dropping a real vulnerable APK into the repo lets the
pipeline exercise its full surface — SAST + Secrets + SCA + DAST + IaC + RASP —
in a single PR, instead of needing a separate build pipeline to produce one.

## Do not ship to production

These samples are flagged by the gate and exist for training only. The
`Severity Gate + PR Comment` check will (correctly) block merges containing
these files.
