declare module 'cloud-scan' {
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

  export type AuditStateType = 'OK' | 'FAIL' | 'UNKNOWN'

  /** The compliance data about the resource */
  export interface AuditResultInterface {
    name?: ResourceFriendlyNameType
    provider: CloudProviderNameType
    physicalId: PhysicalIdType
    region: string
    service: CloudServiceType
    time: ScanTimeType
    rule: RuleNameType
    state: AuditStateType
    profile: string
  }
}
