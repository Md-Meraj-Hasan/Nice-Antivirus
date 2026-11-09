# Nice Antivirus

Kotlin + Python Android security utility. The native Android layer owns permissions, scoped storage access, UI, and Android lifecycle. Python provides the local analysis engine and signature database logic.

## Current status

This is the initial, buildable project scaffold. It is **not yet a production antivirus** and does not claim comprehensive malware detection. Detection currently includes exact SHA-256 matches against locally installed, authenticated signatures plus basic APK metadata/permission review. No automatic deletion is performed.

## Features planned

- Full scan of user-selected and Android-accessible files (SAF / MediaStore scopes)
- APK metadata and requested-permission review
- SHA-256 signature matching and signed database updates
- Quarantine with restore, never silent deletion
- Storage/junk analysis with user-confirmed cleanup
- Scan history and security report
- Automatic + manual signature update
- No ads; no root required

## Architecture

- **Kotlin:** Android app, runtime permissions, Storage Access Framework, WorkManager, notifications, UI
- **Python:** analysis engine, SHA-256 hashing, signature validation/import, rule evaluation
- **Chaquopy:** Python runtime embedded in the Android app
- **SQLite:** local signatures and scan history

## Build

Open the repository in Android Studio (JDK 17 / Android SDK installed), or run the **Build Android APK** GitHub Actions workflow. The workflow builds a debug APK and uploads it as an artifact.

## Signature update format

The updater expects a JSON manifest served over HTTPS:

```json
{
  "schema_version": 1,
  "version": 1,
  "generated_at": "2026-01-01T00:00:00Z",
  "signatures": [
    {
      "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "label": "Example.Test.Detection",
      "severity": "high",
      "description": "Example signature for testing only"
    }
  ]
}
```

The example signature above is illustrative and is not a real malware indicator. The app validates manifest structure and hashes before storing it. Production releases should pin a trusted signing key or use a signed release manifest; HTTPS alone is not a substitute for publisher authenticity.

## Android limitations

Android sandboxes apps. Without root or privileged/device-owner access, this app cannot scan other apps' private data, clear another app's private cache, forcibly free all RAM, repair arbitrary filesystems, or delete files throughout protected storage. It only scans locations the user or OS makes accessible. Files ending in `.bin` are **not** inherently malicious and are never bulk-deleted.

## License

Choose and add a license before redistribution.
