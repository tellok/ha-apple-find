# ha-apple-find

## 0.7.4

### Patch Changes

- 0ae4d5b: Fix Chinese text appearing in the English Apple Account sign-in and two-factor authentication forms. Apple Find now provides translations for 65 Home Assistant locales, including setup, iCloud Contacts options, reauthentication, and entity labels.

## 0.7.3

### Patch Changes

- Check Apple for device locations every 15 seconds under normal conditions,
  matching the interval for automatically discovered contacts. Back off when
  Apple rate-limits requests.

See [GitHub Releases](https://github.com/tellok/ha-apple-find/releases) for the
full 0.7.3 release notes and earlier versions.
