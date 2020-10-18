declare module 'cloud-search' {
  import { Arguments } from 'yargs'

  /** the friendly name of the resource */
  export type ResourceFriendlyNameType = string

  /** the cloud provider's physical ID representing a resource */
  export type PhysicalIdType = string

  /** the cloud provider service name */
  export type CloudServiceType = string

  /** cloud provider name */
  export type CloudProviderNameType = 'aws'

  /** time the resource was last scanned */
  export type ScanTimeType = string

  /** the name of the rule that scanned the resource */
  export type RuleNameType = string

  /** controls how much data is dumped to terminal, silent for testing */
  export type VerbosityType = 'silent' | 'normal'

  export type AuditStateType = 'OK' | 'FAIL' | 'UNKNOWN' | 'WARNING'

  export interface AWSParamsInterface {
    profile: string
    rule: string
    resourceId?: string
    region: string
    verbosity?: VerbosityType
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
    profile: string
    resourceId?: string
    verbosity?: VerbosityType
  }

  interface AWSScannerCliArgsInterface extends AWSScannerInterface, Arguments {}
}
