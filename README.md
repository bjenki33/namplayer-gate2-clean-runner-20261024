# NamPlayer Gate 2 public runner inventory

This public, privacy-safe harness checks whether a disposable GitHub-hosted
runner matches the exact toolchain and Simulator tuple required by NamPlayer
Gate 2. It contains no handoff archive, relink kit, keys, application build
outputs, credentials, provider data, private logs or user content.

The inventory targets the runner tuple specified for NamPlayer commit
`31dcac1459b39899f2cd766edcf4987e46b64981`; it does not authenticate or
checkout that source commit. The required runner tuple is:

- GitHub-hosted macOS on ARM64 using the `xcode-27` image;
- Xcode 27.0 build 27A266a;
- iOS device and Simulator SDK 27.0;
- iOS 27.0 Simulator runtime build 24A434 with arm64 support; and
- the iPhone 18 Pro Simulator device type.

A green inventory run proves only that this public runner image exposes the
required tuple. It does not run the private Gate 2 workload, does not prove the
offline workload predicate and does not admit the dependency for distribution.
Gate 2 and Phase 2 remain `BLOCKED` until every authenticated runner and
external-admission predicate passes.
