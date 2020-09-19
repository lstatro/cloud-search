import { AuditResultInterface } from 'cloud-scan'

interface params {
  name?: string
  provider: string
  physicalId: string
  service: string
  rule: string
  state: string
  region: string
  profile: string
}

export default (params: params) => {
  return {
    ...params,
    time: new Date().toISOString(),
  } as AuditResultInterface
}
