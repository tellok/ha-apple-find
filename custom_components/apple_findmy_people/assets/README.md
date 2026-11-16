# Bundled runtime assets

The MIT License applies only to Apple Find's original code and documentation. The third-party code, binaries, certificates, and artwork listed below remain subject to their respective terms.

- `external/adi` contains the CoreADI emulator from [os-findmy-e](https://github.com/sacca97/os-findmy-e/tree/d4d2a832baf47d1cf43d989879950ac2aec45f47/tools/machoadi). Its TLS client uses normal certificate verification and the bundled Apple CA roots.
- `external/CoreADI.x86_64` is the Apple library extracted from the [iTunes 12.8.3 for Mac installer](https://support.apple.com/kb/DL1977). SHA-256 is `2eafc3c79c7f41a8afbfbeaaf23ee5dab5ad5bda55ec8e54dbc0ddf1d20ce630`.
- `research/vendor/pypush-full` includes the NAC emulator and sample hardware fixture from the [pypush history](https://github.com/JJTech0130/pypush/tree/902965a4108f2d936823f852417701ab96f981fd/emulated), plus the Apple IMDAppleServices library used by that emulator.
- `research/vendor/rustpush` contains the [legacy FairPlay protocol fixture](https://github.com/stek29/rustpush/tree/b2996d57936ccd72198144685c7837ea01759685/certs/legacy-fairplay). The same fixture is published upstream.
- `research/apple-root-ca*.pem` contains public [Apple Root Certificates](https://www.apple.com/certificateauthority/).
- The adjacent `brand` directory contains artwork extracted from the macOS Find My 4.0 application’s `AppIcon.icns`.

Generated account sessions, registration identities, contact share keys, and location snapshots live in Home Assistant’s configuration directory.
