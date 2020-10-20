# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

- AWS - TrailEncrypted
- CHANGELOG.md

## [1.2.0] - 2020-10-19

### Added

- AWS - TrailEvents
- AWS - MultiRegionTrailEnabled

### Changed

- Cli description updates
- AWS class method naming updates to fall in line with project established conventions
- README.md wording

### Removed

## [1.1.1] - 2020-10-18

### Added

- added key words to `package.json`
- added project description to `package.json`
- added author to `package.json`
- added readme to `package.json`

### Changed

- dependency version bump

### Removed

- coveralls will no longer run on pull requests
- deprecated all `1.0.*` builds in npm

## [1.1.0] - 2020-10-18

### Added

- AWS - KeyRotationEnabled
- verbosity option bug fixes

### Changed

- Updated cli to correctly distinguish between a resource and resourceId
- Centralized AWS key type CLI argument
- Refactored the AWS module to export more then just the AWS class
- Refactored all functions and tests to honor resourceId and resource level scans
- Refactored all functions to use audit instead of auditObject
- Refactored VolumesEncrypted scan to use centralized KMS trust system
- Refactored various functions to remove the need to manually define the handler arguments type
- Refactored the spinner and cli output to terminal to account for silent scans mainly to benefit testing
- New scans will now release as minor updates

### Removed