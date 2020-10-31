import { CommandBuilder } from 'yargs'
import {
  AuditResultInterface,
  AWSClientOptionsInterface,
  AWSParamsInterface,
  KeyType,
} from 'cloud-search'
import { KeyMetadata } from 'aws-sdk/clients/kms'
import _AWS from 'aws-sdk'
import Provider from '../Provider'
import assert from 'assert'

interface ScanInterface {
  region?: string
  resourceId?: unknown
}

interface KeyCacheInterface extends KeyMetadata {
  givenKeyId?: string
}

interface AuditInterface {
  [key: string]: unknown
  resource: unknown
  region?: string
}

export const keyTypeArg: CommandBuilder = {
  keyType: {
    alias: 't',
    describe: 'the AWS key type',
    type: 'string',
    default: 'aws',
    choices: ['aws', 'cmk'],
  },
}

export abstract class AWS extends Provider {
  abstract service: string

  region: string
  regions: string[] = []
  global = false
  AWS = _AWS
  keyMetaData: KeyCacheInterface[] = []
  profile?: string
  resourceId?: string
  keyType?: KeyType

  constructor(params: AWSParamsInterface) {
    super(params.rule, params.verbosity, params.format)

    this.region = params.region
    this.profile = params.profile
    this.resourceId = params.resourceId

    this.AWS.config.update({
      maxRetries: 20,
    })

    this.keyType = params.keyType
  }

  abstract async scan(params: ScanInterface): Promise<void>

  abstract audit(params: AuditInterface): Promise<void>

  getDefaultAuditObj = ({
    resource,
    region,
  }: {
    resource: string
    region: string
  }) => {
    return {
      provider: 'aws',
      physicalId: resource,
      service: this.service,
      rule: this.rule,
      region: region,
      state: 'UNKNOWN',
      profile: this.profile,
      time: new Date().toISOString(),
    } as AuditResultInterface
  }

  getOptions = () => {
    let options: AWSClientOptionsInterface
    if (this.profile) {
      const credentials = new this.AWS.SharedIniFileCredentials({
        profile: this.profile,
      })
      options = {
        credentials: {
          accessKeyId: credentials.accessKeyId,
          secretAccessKey: credentials.secretAccessKey,
          sessionToken: credentials.sessionToken,
        },
        region: '',
      }
    } else {
      options = {}
    }
    return options
  }

  listRegions = async () => {
    const options = this.getOptions()
    options.region = 'us-east-1'
    const describeRegions = await new this.AWS.EC2(options)
      .describeRegions()
      .promise()

    const regions: string[] = []

    /** we should have a list of regions, if so for each region get the name and push it to the regions list */
    assert(describeRegions.Regions, 'unable to describe regions')
    for (const region of describeRegions.Regions) {
      assert(region.RegionName, 'region does not have a name')
      regions.push(region.RegionName)
    }
    return regions
  }

  getRegions = async () => {
    /** are we set to do all regions? */
    if (this.region === 'all') {
      /** if this is not a global rule we need to get all regions, if it is, then we default o just one */
      if (this.global === false) {
        /** welp, lets start with by setting us-east-1 and getting a list of all regions */
        const regions = await this.listRegions()
        this.regions = this.regions.concat(regions)
      } else {
        this.region = 'global'
        this.regions.push('us-east-1')
      }
    } else {
      /**
       * looks like this is a single resource request, that resource must
       * live in a specific region and the user should have provided
       * that region.  If t hey didn't then the calling service should fail
       */
      this.regions.push(this.region)
    }
  }

  handleRegions = async () => {
    await this.getRegions()

    for (const region of this.regions) {
      this.handleSpinnerText({ message: region })
      await this.scan({ region })
    }
  }

  start = async () => {
    try {
      this.handleSpinnerStatus({ method: 'start' })
      if (this.resourceId) {
        assert(
          this.region !== 'all',
          'must provide a region for a resource specific scan'
        )
        await this.scan({ region: this.region, resourceId: this.resourceId })
      } else {
        await this.handleRegions()
      }
      this.handleSpinnerStatus({ method: 'succeed' })
    } catch (err) {
      this.handleSpinnerStatus({ method: 'fail', message: err.message })
      /** we want to rethrow this so that tests outright fail and the user can see the reason why */
      throw err
    }
  }

  getKeyMetadata = async (keyId: string, region: string) => {
    const options = this.getOptions()
    try {
      options.region = region
      const kms = new this.AWS.KMS(options)
      const describeKey = await kms
        .describeKey({
          KeyId: keyId,
        })
        .promise()
      if (describeKey.KeyMetadata) {
        const keyMetaData = { ...describeKey.KeyMetadata, givenKeyId: keyId }
        this.keyMetaData = this.keyMetaData.concat(keyMetaData)
      }
      return
    } catch (err) {
      /** do nothing, eat the error and move on */
    }
  }

  findKey = async (keyId: string, region: string) => {
    let matched = this.keyMetaData.find((metaData) => metaData.Arn === keyId)

    /** can we find the key with it's given name? */
    if (!matched) {
      matched = this.keyMetaData.find(
        (metaData) => metaData.givenKeyId === keyId
      )
    }

    /** can we find the key with it's key ID name? */
    if (!matched) {
      matched = this.keyMetaData.find((metaData) => metaData.KeyId === keyId)
    }

    /** is this even a key in AWS? */
    if (!matched) {
      await this.getKeyMetadata(keyId, region)
    }

    /** if the is not in the cache by now, then it doesn't exist */
    return this.keyMetaData.find((metaData) => metaData.givenKeyId === keyId)
  }

  isKeyTrusted = async (keyId: string, type: 'aws' | 'cmk', region: string) => {
    let trusted: 'UNKNOWN' | 'OK' | 'WARNING' | 'FAIL' = 'UNKNOWN'
    const matched = await this.findKey(keyId, region)
    if (matched) {
      if (type === 'aws') {
        trusted = 'OK'
      } else if (type === 'cmk') {
        /**
         * any encryption is better then no encryption, set to warning and
         * override to TRUSTED if this is in fact a CMK
         */
        trusted = 'WARNING'
        if (matched.KeyManager === 'CUSTOMER') {
          trusted = 'OK'
        }
      } else {
        throw new Error('key type must be cmk or aws')
      }
    } else {
      trusted = 'FAIL'
    }
    return trusted
  }

  pager = async <R>(promise: Promise<unknown>, attribute: string) => {
    let resources: R[] = []
    let hasNextPage

    do {
      hasNextPage = false

      /**
       * - wait for the promise to finish
       * - it pains me to use an "any", but we save a lot of pain by doing so
       */
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const result = (await promise) as any

      /** in the result did we find the target response key? */
      if (result[attribute]) {
        /** looks like we did, lets add it to our resource array and move on */
        resources = resources.concat(result[attribute])
      }

      /**
       * honestly AWS always returns a response, I'm checking this because
       * I don't want to go back and update every test.
       *
       * Call me lazy.  I'm good with that.  I'll trade one if check to save
       * possibly hundreds of mocks.  Sounds like a good deal to me.
       */

      /** was there an AWS response object returned with the request? */
      if (result.$response) {
        /** is there another page to the request? */
        hasNextPage = result.$response.hasNextPage()
        if (hasNextPage) {
          /**
           * reset the promise to the next page and iterate.
           * I am not entirely sure the sdk is setup to use .promise off the
           * nextPage function, but it works!  If result wasn't any we would
           * see an error indicating that .promise() is not a method off the
           * nextPage function.
           */
          promise = result.$response.nextPage().promise()
        }
      }
    } while (hasNextPage)

    return resources
  }
}
