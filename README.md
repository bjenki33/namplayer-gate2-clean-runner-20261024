# NamPlayer Gate 2 public runner inventory

This public, privacy-safe harness checks whether a disposable GitHub-hosted
runner matches the exact toolchain and Simulator tuple required by NamPlayer
Gate 2. It contains no handoff archive, relink kit, keys, application build
outputs, credentials, provider data, private logs or user content.

The inventory targets the exact Gate 2 contract runner tuple; it does not
authenticate or checkout application source. The required runner tuple is:

- GitHub-hosted macOS on ARM64 using the `xcode-27` image;
- Xcode 27.0 build 27A266a;
- iOS device and Simulator SDK 27.0;
- iOS 27.0 Simulator runtime build 24A434 with arm64 support; and
- the iPhone 18 Pro Simulator device type; and
- the fixed arm64 Homebrew `gpgv` 2.5.24 executable, resolved to a regular
  file and accepted only after strict code-signature verification. The
  inventory emits only its SHA-256, version and bounded path class.

A green inventory run proves only that this public runner image exposes the
required tuple. It does not admit the dependency for distribution.

The repository also contains one manual-only `Gate 2 private technical proof`
workflow. It checks out no repository and uses no Actions artifact, cache or
release. One exact contract-v2 handoff reaches the disposable runner only as
CMS-encrypted, independently HMAC-authenticated ciphertext through a temporary
one-session broker; the sanitized result/evidence returns through the same
encrypted channel. The workflow receives only temporary environment secrets,
binds the exact repository/workflow commit and deletes no owner data. No
handoff, source, candidate, key, signing material or evidence is stored in this
public repository or its GitHub storage.

The private transport fetches exactly three encrypted inputs: the handoff,
bootstrap runner and preparation receipt. It does not transport an executable;
the fixed runner-image `gpgv` is independently resolved, signature checked and
bound to the exact contract SHA-256 before use.

The private workflow's presence is not proof that it ran or passed. Gate 2 and
Phase 2 remain `BLOCKED` until the contract pins this workflow commit, the exact
fresh result independently verifies, and every internal ESign/physical
predicate passes.
