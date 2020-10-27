import { AuditResultInterface, AWSScannerInterface } from 'cloud-search'
import assert from 'assert'

import { AWS } from '../../../../../lib/aws/AWS'

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
    super({ ...params, rule })
  }

  async audit({ resource, region }: { resource: string; region: string }) {
    const options = this.getOptions()
    options.region = region

    const ec2 = new this.AWS.EC2(options)

    const audit = this.getDefaultAuditObj({ resource, region })

    const describe = await ec2
      .describeSnapshotAttribute({
        SnapshotId: resource,
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
      audit.state = 'FAIL'
    } else {
      audit.state = 'OK'
    }

    this.audits.push(audit)
  }

  scan = async ({
    region,
    resourceId,
  }: {
    region: string
    resourceId: string
  }) => {
    if (resourceId) {
      await this.audit({ resource: resourceId, region })
    } else {
      const snapshots = await this.listSnapshots(region)
      for (const snapshot of snapshots) {
        assert(snapshot.SnapshotId, 'does not have an id')
        await this.audit({ resource: snapshot.SnapshotId, region })
      }
    }
  }
}

export const handler = async (args: AWSScannerInterface) => {
  const scanner = new PublicSnapshot(args)

  await scanner.start()
  scanner.output()
  return scanner.audits
}
