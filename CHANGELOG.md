# Changelog

## Unreleased

### Added

- Guard `ModerateContent` is generally available for content moderation on
  `guard()` (not `protect()`).

### Changed

- Guard default request timeout is 2000 ms (was 1000 ms), matching the JS SDK.

### Deprecated

- `experimental_ModerateContent` is a deprecated alias for `ModerateContent`.
