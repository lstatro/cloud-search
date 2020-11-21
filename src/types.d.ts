declare module '@lstatro/cloud-search' {
  import { Arguments } from 'yargs'

  /** the friendly name of the resource */
  export type ResourceFriendlyNameType = string

  /** the cloud provider's physical ID representing a resource */
  export type PhysicalIdType = string

  /** the cloud provider service name */
  export type CloudServiceType = string

  /** cloud provider name */
  export type CloudProviderNameType = 'aws'

  /** aws kms key types */
  export type KeyType = 'aws' | 'cmk'

  /** time the resource was last scanned */
  export type ScanTimeType = string

  /** the name of the rule that scanned the resource */
  export type RuleNameType = string

  /** controls how much data is dumped to terminal, silent for testing */
  export type VerbosityType = 'silent' | 'normal'

  /** output formatting */
  export type FormatType = 'terminal' | 'json'

  export type AuditStateType = 'OK' | 'FAIL' | 'UNKNOWN' | 'WARNING'

  export interface AWSParamsInterface {
    profile?: string
    rule: string
    resourceId?: string
    region: string
    verbosity?: VerbosityType
    keyType?: KeyType
    format?: FormatType
  }

  /** The compliance data about the resource */
  export interface AuditResultInterface {
    name?: ResourceFriendlyNameType
    provider: CloudProviderNameType
    comment?: string
    physicalId: PhysicalIdType
    region: string
    service: CloudServiceType
    time: ScanTimeType
    rule: RuleNameType
    state: AuditStateType
    profile?: string
  }

  /** aws-sdk client options */
  export interface AWSClientOptionsInterface {
    credentials?: {
      accessKeyId: string
      secretAccessKey: string
      sessionToken: string
    }
    region?: string
  }

  export interface AWSScannerInterface {
    region: string
    keyType?: KeyType
    profile?: string
    resourceId?: string
    verbosity?: VerbosityType
    format?: FormatType
  }

  export interface AWSScannerCliArgsInterface
    extends AWSScannerInterface,
      Arguments {}

  export interface UserReportJson {
    user: string
    arn: string
    user_creation_time: string
    password_enabled: string
    password_last_used: string
    password_last_changed: string
    password_next_rotation: string
    mfa_active: string
    access_key_1_active: string
    access_key_1_last_rotated: string
    access_key_1_last_used_date: string
    access_key_1_last_used_region: string
    access_key_1_last_used_service: string
    access_key_2_active: string
    access_key_2_last_rotated: string
    access_key_2_last_used_date: string
    access_key_2_last_used_region: string
    access_key_2_last_used_service: string
    cert_1_active: string
    cert_1_last_rotated: string
    cert_2_active: string
    cert_2_last_rotated: string
  }
}
