import { AuditResultInterface, AWSScannerInterface } from 'cloud-search'
import { AWS, keyTypeArg } from '../../../../lib/aws/AWS'
import { DBInstance } from 'aws-sdk/clients/neptune'
import assert from 'assert'
const rule = 'InstanceEncrypted'

export const command = `${rule} [args]`

export const desc = `Amazon Neptune graph database instances should have encryption enabled

  OK      - Neptune instance encryption is encrypted at rest
  UNKNOWN - Unable to determine if Neptune instance encryption enabled
  FAIL    - Neptune instance is not encrypted at rest

  resourceId: Database Identifier

`
//TODO: Figure out the resourceId for Neptune.
export const builder = {
  ...keyTypeArg,
}

export default class InstanceEncrypted extends AWS {
  audits: AuditResultInterface[] = []
  service = 'neptune'
  global = false

  constructor(public params: AWSScannerInterface) {
    super({ ...params, rule })
  }

  async audit({ resource, region }: { resource: DBInstance; region: string }) {
    const options = this.getOptions()
    options.region = region
    assert(resource.DBInstanceIdentifier, 'instance missing its DB Identifier')
    const audit = this.getDefaultAuditObj({
      resource: resource.DBInstanceIdentifier,
      region,
    })
    if (resource.KmsKeyId) {
      assert(
        this.keyType,
        'Key type is required arguement for isKeyTrusted check'
      )
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
    resourceId,
    region,
  }: {
    resourceId: string
    region: string
  }) => {
    let instances
    const options = this.getOptions()
    options.region = region
    if (resourceId) {
      const promise = new this.AWS.Neptune(options)
        .describeDBInstances({
          DBInstanceIdentifier: resourceId,
        })
        .promise()
      instances = await this.pager<DBInstance>(promise, 'DBInstances')
    } else {
      const promise = new this.AWS.Neptune(options)
        .describeDBInstances()
        .promise()
      instances = await this.pager<DBInstance>(promise, 'DBInstances')
    }
    for (const instance of instances) {
      await this.audit({ resource: instance, region })
    }
  }
}

export const handler = async (args: AWSScannerInterface) => {
  const scanner = new InstanceEncrypted(args)
  await scanner.start()
  scanner.output()
  return scanner.audits
}
