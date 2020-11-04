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
    // assert(
    //   describeTable.Table.SSEDescription,
    //   'SSEDescription should be defined for the table'
    // )
    // TODO: Need to figure out how to split out keyId
    console.log(
      'this is the describeTable call in audit ...',
      describeTable.Table
    )
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
      let tables = await this.pager<TableName>(promise, 'TableNames')
      for (let table of tables) {
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
