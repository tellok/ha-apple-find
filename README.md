# Apple Find for Home Assistant

<img src="custom_components/apple_findmy_people/brand/icon.png" alt="macOS Find My app icon" width="96">

Apple Find is a custom integration for Home Assistant Core. Its People and Devices clients share one Apple session, provisioned CoreADI state and APNs identity on the HA host. The People client polls Apple for location reports and uses Apple push to receive contact share keys when needed. The Devices client polls Apple's native device service and discovers trackers that provide usable locations.

## Status

Verified on Linux/aarch64 on the Home Assistant host:

- Provision an emulated macOS ADI identity and generate anisette headers.
- Obtain Apple validation data for IDS registration.
- Activate a receiver certificate and establish a TLS-verified APNs connection with a courier token.
- Authenticate an Apple Account with trusted-device 2FA and receive both `mmeFMFAppToken` and `searchPartyToken`.
- Register a Linux IDS receiver for Find My and confirm the receiver's courier token and secure location capabilities through Apple's IDS directory.
- Connect to APNs using a signed connect frame and the existing receiver certificate and token. Verify that the IDS directory returns the public device key and signed prekey corresponding to the Linux receiver's local keys.
- Resolve an existing share through the native Find My People service and submit an accepted SearchParty key-distribution request.
- Receive and authenticate a real Find My IDS message for the configured share, then decrypt its P-224 location key. The observed message used NGM validator version 13.
- Fetch and decrypt fresh location reports with that key. The encrypted payload uses seconds since 2001, and the outer gateway timestamp uses Unix milliseconds. The collector uses the encrypted timestamp, verifies report identity, and publishes latitude, longitude, horizontal accuracy and the optional native floor.

The current macOS Find My daemon was observed issuing `SubscribeAndFetch` with the context `com.apple.findmy.findmylocateagent`. Its request obtains the client ID from AuthKit's device UUID and the token from FindMyDevice's APNs public token. The latter is formatted as uppercase hex, verified against the native formatter with synthetic data. The collector uses these representations and the account's native Friends service hostname.

## Components

- `scripts/apple_probe.py` runs GrandSlam and a scoped MobileMe login with an interactive 2FA prompt. It saves session state and removes the password from the saved account.
- `scripts/emulated_anisette.py` obtains a new OTP as needed from the bundled CoreADI emulator. Home Assistant creates a new ADI identity during first sign-in and stores it with the Apple session.
- `scripts/people_bootstrap.py`, `scripts/ids_enroll.py`, `scripts/ids_register.py` and `scripts/ids_receiver.py` implement the IDS delegate, certificate, registration and receipt stages.
- `custom_components/apple_findmy_people/backend` implements native People, Devices, and Apple authorization. HA Core owns the collectors. Both use one CoreADI provider, and HA config entries determine which contacts and devices to track.
- `custom_components/apple_findmy_people/device_tracker.py` validates normalized location snapshots. Device discovery runs every 120 seconds under normal conditions. Each configured contact defaults to 60 seconds. Requests are backed off on service errors.
- The command-line probes in `scripts` can still be used independently for development.

The emulation and native protocol probes reference the [Zerotistic protocol analysis](https://zerotistic.blog/posts/find-my-people-linux/), [pypush](https://github.com/JJTech0130/pypush), [rustpush](https://github.com/stek29/rustpush) and [os-findmy-e](https://github.com/sacca97/os-findmy-e). See [bundled assets and sources](custom_components/apple_findmy_people/assets/README.md).

## Test

```sh
docker build -f research/Dockerfile -t findmy-people-research:local .
docker run --rm -v "$PWD:/workspace:ro" findmy-people-research:local python -m pytest -q -p no:cacheprovider
```

## Home Assistant setup

On Home Assistant 2026.11 or later, open **Settings → Marketplace → Add from link** and enter `https://github.com/tellok/ha-apple-find`. Install **Apple Find** and restart Home Assistant when prompted.

Home Assistant Marketplace requires public GitHub repositories. While this repository is private, authorized readers can download a release archive through GitHub.

The installation includes the integration code, brand assets, CoreADI emulator and library, Apple trust roots, and enrollment resources. On first sign-in, HA provisions a new ADI identity and stores it in `.findmy-people-headless/state` under its configuration directory. This directory also holds the Apple session, registration keys, contact share keys, and location snapshots. Preserve it when updating an existing Apple Find installation.

Use **Settings → Devices & services → Add integration → Apple Find** to sign in with an Apple Account and the six-digit code shown on a trusted device. Pick device discovery or add a contact using the email or international phone number they already use to share location. Subsequent entries reuse the same authorized Apple session. For an expired session, open the reauthentication flow from **Repairs** when HA posts a notification. **Reconfigure** opens the same login form. Login passwords are excluded from saved state.

Open a tracked device in **Apple Find → Devices** to use its **Play Sound** button. The button appears when Apple advertises the sound capability. Home Assistant checks the device's current Apple identifier and sends the native command when the button is pressed.

For an older deployment that still uses the separate native Devices integration, stop the old collectors and Home Assistant Core. Run `python scripts/migrate_ha_registry.py /config /config/private-migration-backup --apply` on the HA configuration directory, install the combined integration, and start Core. The migration preserves config entry IDs, entity IDs, and existing Apple state. Keep the backup until both clients are verified in Core. The script also supports a dry run and `--restore` while Core is stopped.
