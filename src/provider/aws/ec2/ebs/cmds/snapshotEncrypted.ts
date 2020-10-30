import { CommandBuilder } from 'yargs'
import { Snapshot } from 'aws-sdk/clients/ec2'
import { AuditResultInterface, AWSScannerInterface } from 'cloud-search'
import assert from 'assert'
import { AWS, keyTypeArg } from '../../../../../lib/aws/AWS'

const rule = 'SnapshotEncrypted'

export const command = `${rule} [args]`

export const builder: CommandBuilder = {
  ...keyTypeArg,
}

export const desc = `EBS Snapshots should be encrypted

  OK      - The snapshot is encrypted 
  UNKNOWN - Unable to determine if the snapshot is encrypted
  WARNING - The snapshot is encrypted, but not with the key type
  FAIL    - The snapshot is not encrypted

  resourceId - volume id

`

export default class SnapshotEncrypted extends AWS {
  audits: AuditResultInterface[] = []
  service = 'ebs'

  constructor(public params: AWSScannerInterface) {
    super({ ...params, rule })
  }

  async audit({ resource, region }: { resource: Snapshot; region: string }) {
    assert(resource.SnapshotId, 'snapshot must have a snapshot id')

    const audit = this.getDefaultAuditObj({
      resource: resource.SnapshotId,
      region: region,
    })

    if (resource.KmsKeyId) {
      assert(
        resource.Encrypted === true,
        'key detected, but snapshot reports as not encrypted'
      )
      assert(this.keyType, 'key type is required')
      audit.state = await this.isKeyTrusted(
        resource.KmsKeyId,
        this.keyType,
        region
      )
    } else {
      audit.state = 'FAIL'
    }

    this.audits.push(audit)
  }

  scan = async ({
    region,
    resourceId,
  }: {
    region: string
    resourceId?: string
  }) => {
    const options = this.getOptions()
    options.region = region

    const snapshots = await this.pager<Snapshot>(
      new this.AWS.EC2(options)
        .describeSnapshots({
          OwnerIds: ['self'],
          SnapshotIds: resourceId ? [resourceId] : undefined,
        })
        .promise(),
      'Snapshots'
    )

    for (const snapshot of snapshots) {
      await this.audit({ resource: snapshot, region })
    }
  }
}

export const handler = async (args: AWSScannerInterface) => {
  const scanner = await new SnapshotEncrypted(args)
  await scanner.start()
  scanner.output()
  return scanner.audits
}
