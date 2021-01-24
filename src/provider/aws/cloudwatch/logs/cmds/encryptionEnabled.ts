import { AWS } from '../../../../../lib/aws/AWS'
import { LogGroup } from 'aws-sdk/clients/cloudwatchlogs'
import assert from 'assert'

const rule = 'EncryptionEnabled'

export const command = `${rule} [args]`

export const desc = `Cloudwatch log groups should encrypt at rest with a
CMK

  OK      - The log group is encrypted with a known CMK
  WARNING - The log group is encrypted with a AWS managed KMS key (this should never happen)
  FAIL    - The log group is not encrypted at rest (AWS default encryption)

  resourceId - log group name

  note: AWS encrypts log groups by default using internal keys that the customer
        has no insight or control over.  This is unlike other AWS managed keys
        where they expose the existence of a key in the 'AWS managed keys' tab
        in the KMS console.  This means customers cannot view/list the key or 
        any policy around it.

  note: If a log group comes back as WARNING something unexpected happened.
        For some reason AWS has used a AWS managed account key to encrypt the
        group.  This at the time of writing this scan is unsupported.

  note: If running from gitbash, you may need to escape log groups with '/' in
        the name.  Use CMD or PowerShell if having issues running this specific
        scan.
`

export class SnapshotEncrypted extends AWS {
  audits: AuditResultInterface[] = []
  service = 'cloudwatch'

  constructor(public params: AWSScannerInterface) {
    super({ ...params, rule })

    /** cloudwatch does not support aws managed keys, we want to run all scans as cmk as a result */
    this.keyType = 'cmk'
  }

  async audit({ resource, region }: { resource: LogGroup; region: string }) {
    assert(resource.logGroupName, 'log group must have a name')
    const audit = this.getDefaultAuditObj({
      resource: resource.logGroupName,
      region: region,
    })

    if (resource.kmsKeyId) {
      assert(this.keyType, 'key type is required')
      audit.state = await this.isKeyTrusted(
        resource.kmsKeyId,
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
    const promise = new this.AWS.CloudWatchLogs(options)
      .describeLogGroups({
        logGroupNamePrefix: resourceId,
      })
      .promise()

    const logs = await this.pager<LogGroup>(promise, 'logGroups')

    for (const log of logs) {
      await this.audit({ resource: log, region })
    }
  }
}

export const handler = async (args: AWSScannerInterface) => {
  const scanner = await new SnapshotEncrypted(args)
  await scanner.start()
  scanner.output()
  return scanner.audits
}
