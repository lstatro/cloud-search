declare module '@lstatro/cloud-search' {}

declare interface AWSScannerCliArgsInterface
  extends AWSScannerInterface,
    Arguments {}

/** the friendly name of the resource */
declare type ResourceFriendlyNameType = string

/** the cloud provider's physical ID representing a resource */
declare type PhysicalIdType = string

/** the cloud provider service name */
declare type CloudServiceType = string

/** cloud provider name */
declare type CloudProviderNameType = 'aws'

/** aws kms key types */
declare type AWSKeyType = 'aws' | 'cmk'

/** time the resource was last scanned */
declare type ScanTimeType = string

/** the name of the rule that scanned the resource */
declare type RuleNameType = string

/** controls how much data is dumped to terminal, silent for testing */
declare type VerbosityType = 'silent' | 'normal'

/** output formatting */
declare type FormatType = 'terminal' | 'json'

declare type AuditStateType = 'OK' | 'FAIL' | 'UNKNOWN' | 'WARNING'

declare interface AWSScannerInterface {
  region: string
  keyType?: AWSKeyType
  profile?: string
  resourceId?: string
  verbosity?: VerbosityType
  format?: FormatType
}

declare interface AWSParamsInterface {
  profile?: string
  rule: string
  resourceId?: string
  region: string
  verbosity?: VerbosityType
  keyType?: AWSKeyType
  format?: FormatType
}

/** The compliance data about the resource */
declare interface AuditResultInterface {
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
declare interface AWSClientOptionsInterface {
  credentials?: {
    accessKeyId: string
    secretAccessKey: string
    sessionToken: string
  }
  region?: string
}

declare interface UserReportJsonInterface {
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
