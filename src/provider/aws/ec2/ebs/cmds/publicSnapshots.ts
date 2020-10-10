import {
  AuditResultInterface,
  AWSScannerInterface,
  AWSScannerCliArgsInterface,
} from 'cloud-search'
import assert from 'assert'

import AWS from '../../../../../lib/aws/AWS'

const rule = 'PublicSnapshot'

export const command = `${rule} [args]`

export const desc = `SQS topics must be encrypted

  OK      - Snapshot is not public
  UNKNOWN - Unable to determine if snapshot is public
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

  async audit(snapshotId: string, region: string) {
    const options = this.getOptions()
    options.region = region

    const ec2 = new this.AWS.EC2(options)

    const auditObject: AuditResultInterface = {
      name: snapshotId,
      provider: 'aws',
      physicalId: snapshotId,
      service: this.service,
      rule: this.rule,
      region: region,
      state: 'UNKNOWN',
      profile: this.profile,
      time: new Date().toISOString(),
    }

    const describe = await ec2
      .describeSnapshotAttribute({
        SnapshotId: snapshotId,
        Attribute: 'createVolumePermission',
      })
      .promise()

    let isPublic = false
    if (describe.CreateVolumePermissions) {
      for (const permission of describe.CreateVolumePermissions) {
        if (permission.Group === 'all') {
          isPublic = true
        }
      }
    }

    if (isPublic) {
      auditObject.state = 'FAIL'
    } else {
      auditObject.state = 'OK'
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
        assert(snapshot.SnapshotId, 'does not have an id')
        await this.audit(snapshot.SnapshotId, region)
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
