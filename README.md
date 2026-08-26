# AndLua APK Protector

Android app that double-encrypts `assets/*.lua` inside an AndLua APK, injects a runtime decrypt gate, and auto-signs the result.

Built by GitHub Actions. Install the APK from [Releases](https://github.com/panelforsale080-byte/AndLua-APK-Protector/releases).

## What it does

1. You open **AndLua Protector** and select an APK.
2. Every `assets/**/*.lua` file is wrapped with **AES-256-GCM** (`ALP2` header). The original AndLua `=IA` ciphertext stays as the inner layer.
3. A small runtime dex + launcher gate is injected so the protected app still boots: it decrypts lua into the app files dir, then starts the original launcher.
4. Old signatures are stripped and the APK is signed v1/v2/v3.

Framework files under `lua/` are copied through at runtime but not re-encrypted. Other APK entries are left alone.

## Build

```bash
./gradlew :app:assembleRelease
```

APK output: `app/build/outputs/apk/release/`

CI: push to `main` or run **Actions → Build AndLua Protector APK → Run workflow**.

## Notes

- The protected APK uses a new signing cert, so it cannot update-install over the original.
- Client-side wrapping stops casual `=IA` dumpers. A determined reverse engineer who extracts the runtime key can still unwrap. That is the limit of on-device protectors.
- Revoke any GitHub personal access token that was pasted into chat after the repo is up.
