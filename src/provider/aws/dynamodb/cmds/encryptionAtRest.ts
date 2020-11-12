import { AuditResultInterface, AWSScannerInterface } from 'cloud-search'
import { AWS, keyTypeArg } from '../../../../lib/aws/AWS'
import { TableName } from 'aws-sdk/clients/dynamodb'
import assert from 'assert'
const rule = 'EncryptionAtRest'

export const command = `${rule} [args]`

export const desc = `Amazon DynamoDB should have encryption at rest enabled

  OK      - Table is encrypted at rest
  WARNING - Table encrypted but not with the correct key type
  UNKNOWN - Unable to determine if Neptune instance encryption enabled
  FAIL    - Table is not encrypted at rest

  resourceId: Table Name

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
    try {
      const describeTable = await new this.AWS.DynamoDB(options)
        .describeTable({
          TableName: resource,
        })
        .promise()
      assert(describeTable.Table, 'Table should be returned from api call')
      if (describeTable.Table.SSEDescription) {
        assert(
          describeTable.Table.SSEDescription.KMSMasterKeyArn,
          'Table should have a kms key ARN by this point.'
        )
        const kmsKeyArn = describeTable.Table.SSEDescription.KMSMasterKeyArn
        assert(
          this.keyType,
          'Key type is required argument for isKeyTrusted check'
        )
        audit.state = await this.isKeyTrusted(kmsKeyArn, this.keyType, region)
      } else {
        audit.state = 'WARNING'
      }
    } catch (error) {
      /**
       * We wanted to default to unknown because the table is always encrypted
       * by default. Due to the nature of how compliance is determined we reach
       * this catch while checking a table that was encrypted with cmk or aws
       * managed key but were unable to determine compliance confidently.
       */
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
