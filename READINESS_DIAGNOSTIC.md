# Simulator readiness comparison

This synthetic diagnostic compares the existing sequence of isolated HOME,
CFFIXED_USER_HOME and TMPDIR contexts with one stable native account context.
It does not build or launch NamPlayer, consume a private handoff or dependency
kit, or count as a Gate 2 technical proof.

The branch-only push workflow runs two matrix jobs on separate fresh
`xcode-27` runners. Both jobs require image version `20261023.0307.1`, Xcode
27.0 build 27A266a and iOS runtime 27.0 build 24A434 on arm64. Each job executes
the same ordered Simulator commands, uses the default device-set behavior,
creates one randomly named owned iPhone 18 Pro and cleans up only its target.
The private technical proof workflow and its main-branch commit stay unchanged.

The sequence includes runtime/device-type context probes, creation, boot,
bootstatus, installation of a generated synthetic CA, exact identity, listapps,
shutdown, deletion and independent absence verification. Every command has a
time and output bound; cleanup has a separate shared deadline. Main failure
and cleanup are reported independently. An unconfirmed create completion or
cleanup error prevents a cleanup PASS. The generated CA private key is removed.

Only static labels, platform versions, booleans, timings, byte counts and
SHA-256 digests leave the runner. Device identifiers, process identifiers,
account names, filesystem paths and raw command output never enter the receipt.
No Actions artifact, cache, release, signing identity or user source is used.

If both jobs pass, the failure was not reproduced by this lightweight sequence.
If one passes and one fails, the result supports an environment effect but
needs a cold confirmation before attributing causality. The experiment omits
FFmpeg/application builds, their load and Xcode service side effects. It does
not prove playback, license compliance, full CI, physical-device acceptance,
or Gate 2 closure.

Run local non-Simulator checks with:

```sh
python3 -m unittest discover -s tests -v
```
