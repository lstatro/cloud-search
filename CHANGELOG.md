# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

- EFS - EncryptionEnabled
- Cloudwatch Logs - EncryptionEnabled

- AWS - EFS - EncryptionEnabled

## [1.11.0] - 2020-11-28

### Added

- AWS - S3 - VersioningEnabled
- AWS - SecretsManager - RotationEnabled
- AWS - IAM - user - RootUserMfaEnabled
- AWS - IAM - user - UserMfaEnabled
- AWS - EMR - SecurityConfiguration
- AWS - EMR - LoggingEnabled
- AWS - EMR - SecurityConfigDiskEncryption
- AWS - EMR - SecurityConfigS3Encryption
- AWS - EMR - SecurityConfigTransitEncryption

### Changed

- various test coverage improvements

### Removed

## [1.10.1] - 2020-11-18

### Added

### Changed

- package.json readme reference update
- force npm to correctly display cloud-search's README.md

### Removed

## [1.10.0] - 2020-11-18

### Added

- AWS - EC2 - VPC - FlowLogsEnabled

### Changed

### Removed

## [1.9.0] - 2020-11-17

### Added

- AWS - EC2 - xLB - DesyncMitigationMode
- AWS - EC2 - xLB - WafEnabled
- AWS - EC2 - xLB - AccessLogsEnabled
- AWS exports module

### Changed

- module names now consistent with ambient module naming, done to support type definition exports
- updated npm keywords with alb, elb, waf

### Removed

## [1.8.0] - 2020-11-11

### Added

- AWS - DynamoDB - EncryptedAtRest
- AWS - EC2 - ELB - DesyncMitigationMode
- AWS - EC2 - ELB - AccessLogsEnabled
- AWS - EC2 - ALB - AccessLogsEnabled

### Changed

### Removed

## [1.7.0] - 2020-11-2

### Added

- Neptune encrypted cluster audit
- Neptune encrypted instance audit

### Changed

- refactor resource listing
- `package.json` `main` attribute outputs scan classes
- fixed bug with async/await in ebs volumeEncrypted

### Removed

## [1.6.1] - 2020-10-27

### Added

### Changed

- centralized audit object creation across all services

### Removed

## [1.6.0] - 2020-10-26

### Added

- AWS - iam, groups - HasManagedAdmin
- AWS - iam, roles - HasManagedAdmin
- AWS - guardduty - DetectorEnabled
- AWS - guardduty - DetectorExists
- AWS - guardduty - DetectorDataSources

### Changed

- fixed region reference as `all` when it should have been `global`

### Removed

## [1.5.0] - 2020-10-24

### Added

- AWS - elasticache - TransitEncryptionEnabled
- AWS - iam, users - HasManagedAdmin
- terminal output as JSON

### Changed

- service arg and class constructor param changes no longer require manual updating should the cli's argument interface change in the future

### Removed

## [1.4.0] - 2020-10-22

### Added

- AWS - ebs - SnapshotEncrypted
- AWS - elasticache - EncryptionAtRest
- updated cli description format

### Changed

- updated documentation formatting
- enforcing file naming conventions

### Removed

## [1.3.0] - 2020-10-20

### Added

- AWS - TrailEncrypted
- CHANGELOG.md

### Changed

- removed unnecessary keyId references

### Removed

## [1.2.0] - 2020-10-19

### Added

- AWS - cloudtrail - TrailEvents
- AWS - cloudtrail - MultiRegionTrailEnabled

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

- AWS - kms - KeyRotationEnabled
- verbosity option bug fixes

### Changed

- Updated cli to correctly distinguish between a resource and resourceId
- Centralized AWS key type CLI argument
- Refactored the AWS module to export more then just the AWS class
- Refactored all functions and tests to honor resourceId and resource level scans
- Refactored all functions to use audit instead of auditObject
- Refactored VolumeEncrypted scan to use centralized KMS trust system
- Refactored various functions to remove the need to manually define the handler arguments type
- Refactored the spinner and cli output to terminal to account for silent scans mainly to benefit testing
- New scans will now release as minor updates

### Removed
