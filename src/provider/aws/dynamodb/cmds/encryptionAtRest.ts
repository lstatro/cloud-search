import { AuditResultInterface, AWSScannerInterface } from 'cloud-search'
import { AWS, keyTypeArg } from '../../../../lib/aws/AWS'
import { TableName } from 'aws-sdk/clients/dynamodb'
import assert from 'assert'
const rule = 'EncryptionAtRest'

export const command = `${rule} [args]`

export const desc = `Amazon DynamoDB should have encryption at rest enabled

  OK      - Neptune instance encryption is encrypted at rest
  UNKNOWN - Unable to determine if Neptune instance encryption enabled
  FAIL    - Neptune instance is not encrypted at rest

  resourceId: Database Identifier

`
export const builder = {
  ...keyTypeArg,
}

export default class EncryptionAtRest extends AWS {
  audits: AuditResultInterface[] = []
  service = 'dynamodb'
  global = false

  constructor(public params: AWSScannerInterface) {
    super({ ...params, rule })
  }

  async audit({ resource, region }: { resource: string; region: string }) {
    const options = this.getOptions()
    options.region = region
    const audit = this.getDefaultAuditObj({
      resource: resource,
      region,
    })
    const describeTable = await new this.AWS.DynamoDB(options)
      .describeTable({
        TableName: resource,
      })
      .promise()
    assert(describeTable.Table, 'Table should be returned from api call')
    const sseDescription = describeTable.Table.SSEDescription
    if (sseDescription) {
      assert(
        describeTable.Table.SSEDescription,
        'Table should have SSEDescription by this point.'
      )
      assert(
        describeTable.Table.SSEDescription.KMSMasterKeyArn,
        'Table should have a kms key ARN by this point.'
      )
      const kmsKeyArn = describeTable.Table.SSEDescription.KMSMasterKeyArn
      const splitKmsKeyArn = kmsKeyArn.split('/')
      assert(
        splitKmsKeyArn.length === 2,
        'KMS key arn split by / should have 2 items in the resulting array'
      )
      const kmsKeyId = splitKmsKeyArn[1]
      assert(
        this.keyType,
        'Key type is required argument for isKeyTrusted check'
      )
      audit.state = await this.isKeyTrusted(kmsKeyId, this.keyType, region)
    } else {
      audit.state = 'WARNING'
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
    const options = this.getOptions()
    options.region = region
    if (resourceId) {
      const describeTable = await new this.AWS.DynamoDB(options)
        .describeTable({
          TableName: resourceId,
        })
        .promise()
      assert(
        describeTable.Table,
        'There should be a table returned from api call'
      )
      assert(
        describeTable.Table.TableName,
        'The table returned from api should have a TableName defined'
      )
      await this.audit({ resource: describeTable.Table.TableName, region })
    } else {
      const promise = new this.AWS.DynamoDB(options).listTables().promise()
      const tables = await this.pager<TableName>(promise, 'TableNames')
      for (const table of tables) {
        await this.audit({ resource: table, region })
      }
    }
  }
}

export const handler = async (args: AWSScannerInterface) => {
  const scanner = new EncryptionAtRest(args)
  await scanner.start()
  scanner.output()
  return scanner.audits
}
