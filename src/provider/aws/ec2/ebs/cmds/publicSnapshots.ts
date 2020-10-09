import {
  AuditResultInterface,
  AWSScannerInterface,
  AWSScannerCliArgsInterface,
} from 'cloud-search'

import AWS from '../../../../../lib/aws/AWS'

const rule = 'PublicSnapshot'

export const command = `${rule} [args]`

export const desc = `SQS topics must be encrypted

  OK      - Snapshot is not public
  UNKNOWN - Unable to determine if snapshot is public
  WARNING - snapshot shared with another account
  FAIL    - Snapshot is public

  resourceId - snapshot id

`

export default class PublicSnapshot extends AWS {
  audits: AuditResultInterface[] = []
  service = 'ebs'
  global = false

  constructor(public params: AWSScannerInterface) {
    super({
      profile: params.profile,
      resourceId: params.resourceId,
      domain: params.domain,
      region: params.region,
      rule,
    })
  }

  async audit(queue: string, region: string) {
    const options = this.getOptions()
    options.region = region

    const auditObject: AuditResultInterface = {
      name: queue,
      provider: 'aws',
      physicalId: queue,
      service: this.service,
      rule: this.rule,
      region: region,
      state: 'UNKNOWN',
      profile: this.profile,
      time: new Date().toISOString(),
    }

    this.audits.push(auditObject)
  }

  scan = async ({
    region,
    resourceId,
  }: {
    region: string
    resourceId: string
  }) => {
    if (resourceId) {
      await this.audit(resourceId, region)
    } else {
      const snapshots = await this.listSnapshots(region)
      for (const snapshot of snapshots) {
        await this.audit(snapshot, region)
      }
    }
  }
}

export const handler = async (args: AWSScannerCliArgsInterface) => {
  const scanner = new PublicSnapshot({
    region: args.region,
    profile: args.profile,
    resourceId: args.resourceId,
    domain: args.domain,
  })

  await scanner.start()
  scanner.output()
  return scanner.audits
}
