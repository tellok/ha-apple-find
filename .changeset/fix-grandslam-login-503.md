---
"ha-apple-find": patch
---

Fix Apple ID sign-in failures caused by GrandSlam returning HTTP 503 for the `macOS` client label. Use the compatible `Mac OS X` label for new and existing ADI identities without requiring users to reset their integration.
