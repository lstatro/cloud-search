/** TODO: can this be handled by iam.simulatePrincipalPolicy? */

import { AuditResultInterface, AWSScannerInterface } from 'cloud-search'
import assert from 'assert'
import AWS from '../../../../../lib/aws/AWS'

const rule = 'PublicRole'

export const command = `${rule} [args]`

export const desc = `Roles must not allow * in trust policy principal

  OK      - Role does not allow * in the trust document principal
  UNKNOWN - unable view the trust policy
  WARNING - role allows for public access under a specific condition more investigation is required
  FAIL    - Role allows * in the trust document principal

  note: iam is global, passing in a region won't change results
  note: this does not take into account the statement ACTION, this means that even DENY statements will flag as
        an issue.  
`

interface TypeHandlerInterface {
  principal: unknown
  statement: {
    Condition?: unknown
  }
}

type isPublic = boolean | 'WARNING'

type PrincipalHandler = (params: TypeHandlerInterface) => isPublic[]

export default class PublicRole extends AWS {
  audits: AuditResultInterface[] = []
  service = 'iam'
  global = true

  constructor(public params: AWSScannerInterface) {
    super({
      profile: params.profile,
      resourceId: params.resourceId,
      region: params.region,
      verbosity: params.verbosity,
      rule,
    })
  }

  handleString = (params: TypeHandlerInterface) => {
    let isPublic: isPublic = false
    if (params.principal === '*') {
      isPublic = true
      if (params.statement.Condition) {
        isPublic = 'WARNING'
      }
    }
    return [isPublic]
  }

  handleArray = (params: TypeHandlerInterface) => {
    assert(Array.isArray(params.principal), 'principal is not an array')
    let isPublicArr: isPublic[] = []
    for (const principal of params.principal) {
      const isPublic = this.handleString({
        principal,
        statement: params.statement,
      })

      isPublicArr = isPublicArr.concat(isPublic)
    }
    return isPublicArr
  }

  handleObject = (params: TypeHandlerInterface) => {
    let isPublicArr: isPublic[] = []
    assert(Array.isArray(params.principal), 'principal is not an array')
    isPublicArr = isPublicArr.concat(this.handleArray(params))
    return isPublicArr
  }

  async audit({
    policyDocument,
    resourceId,
  }: {
    policyDocument: string
    resourceId: string
  }) {
    const auditObject: AuditResultInterface = {
      provider: 'aws',
      physicalId: resourceId,
      service: this.service,
      rule: this.rule,
      region: 'global',
      state: 'UNKNOWN',
      profile: this.profile,
      time: new Date().toISOString(),
    }

    const trust = JSON.parse(decodeURIComponent(policyDocument))

    const handler: { [key: string]: PrincipalHandler } = {
      string: this.handleString,
      object: this.handleObject,
    }

    let isPublicArr: isPublic[] = []

    for (const statement of trust.Statement) {
      if (statement.Principal.AWS) {
        const type = typeof statement.Principal.AWS
        isPublicArr = isPublicArr.concat(
          handler[type]({ principal: statement.Principal.AWS, statement })
        )
      }
    }

    if (isPublicArr.includes(true)) {
      auditObject.state = 'FAIL'
    } else if (isPublicArr.includes('WARNING')) {
      auditObject.state = 'WARNING'
    } else {
      auditObject.state = 'OK'
    }

    this.audits.push(auditObject)
  }

  scan = async ({ resourceId }: { resourceId: string }) => {
    if (resourceId) {
      const iam = new this.AWS.IAM(this.options)
      const getRole = await iam
        .getRole({
          RoleName: resourceId,
        })
        .promise()
      assert(getRole.Role, 'unable to find role')
      assert(
        getRole.Role.AssumeRolePolicyDocument,
        'unable to find trust document'
      )
      await this.audit({
        resourceId,
        policyDocument: getRole.Role.AssumeRolePolicyDocument,
      })
    } else {
      const roles = await this.listRoles()

      for (const role of roles) {
        assert(role.AssumeRolePolicyDocument, 'no trust doc found')
        await this.audit({
          resourceId: role.RoleName,
          policyDocument: role.AssumeRolePolicyDocument,
        })
      }
    }
  }
}

export const handler = async (args: AWSScannerInterface) => {
  const scanner = new PublicRole({
    region: args.region,
    profile: args.profile,
    resourceId: args.resourceId,
    verbosity: args.verbosity,
  })

  await scanner.start()
  scanner.output()
  return scanner.audits
}
