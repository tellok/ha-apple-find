# Live location for a selected contact

The native Find My app can request continuing location updates for a friend who shares their location. The researchers who studied the online People service showed a request with a `live` mode. Their paper describes the sharing phone taking a fresh fix and the viewer receiving silent pushes. The published material does not identify the APNs topic for those fixes or specify a current macOS renewal interval or end-of-session message. [Research presentation, “Normal location sharing”](https://objectivebythesea.org/v6/talks/OBTS_v6_jClassen_aHeinrich.pdf#page=56) · [NDSS paper, §V-D](https://ndss-symposium.org/wp-content/uploads/2025-124-paper.pdf#page=8)

In this integration, each contact check selects the friend, requests reports in `shallow` mode, and closes its client. A SearchParty notification queues an early check of the configured shares. The position published to HA comes from the subsequent fetch response. The integration currently has no per-contact live session. [People collector](../custom_components/apple_find/backend/native_people.py) · [Request construction](../custom_components/apple_find/protocol.py) · [Push handling](../custom_components/apple_find/backend/people_keys.py)

## Open-source comparisons

- OpenBubbles records which friend the user selects and requests a refresh. Its map registers a location event listener and also starts a five-second refresh timer. Changes on the map alone cannot distinguish those paths. [Map lifecycle](https://github.com/OpenBubbles/openbubbles-app/blob/eed1b6332efbb17adbf5ebfa2263ad770169f75e/lib/app/layouts/findmy/findmy_page.dart#L82-L109) · [Friend selection](https://github.com/OpenBubbles/openbubbles-app/blob/eed1b6332efbb17adbf5ebfa2263ad770169f75e/rust/src/api/api.rs#L2098-L2112)
- BlueBubbles Server v1.9.5 describes forwarding location changes obtained on a Mac to connected clients. This architecture places the Apple-facing session on the Mac. [Server release notes](https://github.com/BlueBubblesApp/bluebubbles-server/releases/tag/v1.9.5)

## Verifying a live session

Use one agreed test share. Record the time of opening and closing its card in the native app as a reference. Test the integration separately with the native card closed so both viewers' requests cannot account for the same run.

1. Establish a baseline with the integration's normal polling. Record the triggers, request counts, and source report timestamps.
2. Start one candidate session for the same contact. Record each inbound event, any follow-up fetch, and whether the newest report timestamp advances. Account for scheduled polls separately. Repeated coordinates may still be a new fix if the source timestamp advances.
3. Look for at least two successive timestamp advances after that single start, attributable to inbound events between scheduled polls. Report whether the events delivered a fix or prompted a fetch. A successful start response or a single fresh snapshot establishes neither continuous delivery nor the cause of the update.
4. End the session. Check whether session-specific updates cease and ordinary polling continues. Record the observation window so a quiet period is distinguishable from a confirmed end.

The offline household test feeds notifications and fetch responses through the collector. It checks newer, duplicate, and out-of-order reports and verifies the saved source timestamp. Apple delivery and native-session lifetime require a separate device test. [Household test](../tests/test_people_keys.py)
