# KeyStoreGen

An Android app that creates an app signing key on your phone, the same as
`keytool -genkeypair`, and gets it where it needs to go: your CI secrets, your
password manager and, optionally, your computer. Nothing leaves the phone unless
you save or copy it.

- RSA 4096 (default), RSA 3072, RSA 2048 or EC P-256, in a PKCS#12 keystore
- **Or import an existing keystore**: a `.jks`/`.keystore`/`.p12` file (PKCS#12 or the
  older JKS format, also with a separate key password), a Bitwarden JSON export
  (plain or password protected, PBKDF2 or Argon2id), or pasted base64. The file is kept
  byte for byte, so CI signs with exactly the keystore you already have
- Generated 32-character password, or your own
- Optional certificate details (CN, O, OU, L, ST, C)
- SHA-256 and SHA-1 fingerprints (for Firebase, Google Sign-In, Play)
- **Sign in with GitHub, pick a repository, and add all four secrets in one tap.**
  Values are encrypted on the phone with the repository's public key (libsodium sealed
  box, as GitHub requires); existing secrets are only replaced after you confirm
- Or copy the secrets one by one; clips are marked sensitive
- Password-protected Bitwarden export (one secure note with everything)
- Saves the `.jks` and a matching `signing.properties`
- Secret name prefix, for repositories that sign several apps
- Built-in setup guide with ready-to-copy keytool, workflow and Gradle snippets
- Material 3 with dynamic color, dark mode; screenshots are blocked while secrets are on screen

## How to add signing keys

Only the app APK (or app bundle) needs a key. Anything that is never installed as an
app, such as patch bundles or plugins, isn't checked for a signature.

1. **Create a keystore once and back it up.** If you lose it you can never publish an
   update that installs over the old app. Use this app (or import the one you already
   have, then continue with step 3), or keytool on your computer:

   ```sh
   keytool -genkeypair -v -keystore keystoregen.jks -alias keystoregen \
     -keyalg RSA -keysize 4096 -validity 36500
   ```

   It asks for a keystore password and a key password, plus name details, which can be
   anything. Pressing Enter at the key-password prompt reuses the keystore password.

2. **Encode the keystore as base64** (the app shows the base64 value directly):

   ```sh
   base64 -w0 keystoregen.jks > keystore.txt      # Linux
   base64 -i keystoregen.jks -o keystore.txt      # macOS
   ```

3. **Add four repository secrets** at github.com/OWNER/REPO → Settings → Secrets and
   variables → Actions → New repository secret:

   | Secret                    | Value                                |
   |---------------------------|--------------------------------------|
   | `KEYSTORE`                | the contents of `keystore.txt`       |
   | `KEYSTORE_PASSWORD`       | the keystore password                |
   | `KEYSTORE_ALIAS`          | the `-alias` above                   |
   | `KEYSTORE_ALIAS_PASSWORD` | the key password                     |

   After that, for this repository:
   - **Releases** (`v*` tags): every release is signed with your key, and the
     "throwaway debug key" warning in the release notes goes away. A stable release
     (a tag without `-suffix`, e.g. `v1.2.0`) fails on purpose until these secrets exist.
   - **Nightly builds:** CI also publishes a signed "Nightly Build" release on each
     push to `main`.

4. **Optional: signed builds on your computer.** Put the `.jks` in the repo root and
   create `signing.properties` next to it. Both are git-ignored.

   ```properties
   KEYSTORE_PASSWORD=...
   KEYSTORE_ALIAS=keystoregen
   KEYSTORE_ALIAS_PASSWORD=...
   KEYSTORE_FILE=../keystoregen.jks
   ```

   The `../` is needed because the path is relative to the `app/` folder.

**Changing keys means one more uninstall:** Android requires the same key for updates,
so the first signed release can't install over a debug-signed build. Uninstalling also
resets the app's data. Add the secrets before anyone relies on your builds, then re-run
the latest release so it's signed with your key, and users only have to uninstall once.

## Sign in with GitHub

The app signs in with GitHub's [device flow](https://docs.github.com/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps#device-flow):
it shows a code, you enter it at github.com/login/device, done. No password ever
reaches the app. This needs a GitHub OAuth app, once:

1. github.com → Settings → Developer settings → OAuth Apps → **New OAuth App**.
   Any name and homepage; the callback URL isn't used (e.g. `https://github.com`).
2. In the new app, tick **Enable Device Flow** and save. You don't need a client secret.
3. Put its **Client ID** into the build. It is public by design:
   - locally: `githubClientId=Ov23…` in `gradle.properties`, or
   - in CI: a repository **variable** (not secret) `GH_OAUTH_CLIENT_ID`
     (Settings → Secrets and variables → Actions → Variables).

The app asks for the `repo` scope, the only classic scope that can write Actions
secrets. Without a client ID in the build, or if you prefer narrower access, sign in
with a **fine-grained personal access token** instead, limited to the repositories you
need, with the permission *Secrets: Read and write*.

The token is stored encrypted with a key in the Android Keystore and never leaves the
phone except to talk to api.github.com. Sign out in the app removes it; to revoke it,
go to github.com → Settings → Applications.

Writing secrets requires admin access to the repository (or the token permission above).

## Building

```sh
./gradlew assembleDebug          # debug build
./gradlew testDebugUnitTest      # unit tests
./gradlew assembleRelease        # signed if signing.properties or the env vars exist,
                                 # otherwise with the debug key
```

Requires JDK 17+ and the Android SDK (compileSdk 36). Min. Android 10.
