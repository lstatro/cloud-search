import { AWSClientOptionsInterface } from 'cloud-search'
import _AWS from 'aws-sdk'
import Provider from '../Provider'

import assert from 'assert'
import { Bucket } from 'aws-sdk/clients/s3'
import { InternetGateway, SecurityGroup, Volume } from 'aws-sdk/clients/ec2'
import { KeyListEntry, KeyMetadata } from 'aws-sdk/clients/kms'
import { User } from 'aws-sdk/clients/iam'
import { Topic } from 'aws-sdk/clients/sns'

interface AWSParamsInterface {
  profile: string
  rule: string
  resourceId?: string
  domain: string
  region: string
}

interface ScanInterface {
  region: string
  resourceId?: string
}

export default abstract class AwsService extends Provider {
  abstract service: string

  options: AWSClientOptionsInterface

  domain: string
  region: string
  regions: string[] = []
  global = false
  AWS = _AWS
  keyMetaData?: KeyMetadata[]
  profile?: string
  resourceId?: string

  constructor(params: AWSParamsInterface) {
    super(params.rule)

    this.domain = params.domain
    this.region = params.region
    this.profile = params.profile
    this.resourceId = params.resourceId

    this.AWS.config.update({
      maxRetries: 20,
    })

    this.options = this.getOptions()
  }

  abstract async scan(params: ScanInterface): Promise<void>

  abstract audit(resource: unknown, region: string): Promise<void>

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

  describeRegions = async () => {
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
    /** is this pub or gov clouds? */

    if (this.domain === 'pub') {
      /** are we set to do all regions? */
      if (this.region === 'all') {
        /** if this is not a global rule we need to get all regions, if it is, then we default o just one */
        if (this.global === false) {
          /** welp, lets start with by setting us-east-1 and getting a list of all regions */
          const regions = await this.describeRegions()
          this.regions = this.regions.concat(regions)
        } else {
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

      /** go read the comments for pub cloud and repeat for gov cloud :P */
    } else if (this.domain === 'gov') {
      if (this.region === 'all') {
        /** if this is not a global rule we need to get all regions, if it is, then we default o just one */
        if (this.global === false) {
          this.options.region = 'us-gov-west-1'
          const describeRegions = await new this.AWS.EC2(this.options)
            .describeRegions()
            .promise()
          assert(describeRegions.Regions, 'unable to describe regions')
          for (const region of describeRegions.Regions) {
            assert(region.RegionName, 'region does not have a name')
            this.regions.push(region.RegionName)
          }
        } else {
          this.regions.push('us-gov-west-1')
        }
      } else {
        this.regions.push(this.region)
      }
    }
  }

  handleRegions = async () => {
    await this.getRegions()

    for (const region of this.regions) {
      this.spinner.text = region
      await this.scan({ region })
    }
  }

  start = async () => {
    try {
      this.spinner.start()
      if (this.resourceId) {
        await this.scan({ region: this.region, resourceId: this.resourceId })
      } else {
        await this.handleRegions()
      }
      this.spinner.succeed()
    } catch (err) {
      this.spinner.fail(err.message)
    }
  }

  describeInternetGateways = async (region: string, resourceId?: string) => {
    const options = this.getOptions()
    options.region = region

    const ec2 = new this.AWS.EC2(options)

    let nextToken: string | undefined

    let igws: InternetGateway[] = []

    do {
      const describeInternetGateways = await ec2
        .describeInternetGateways({
          NextToken: nextToken,
          InternetGatewayIds: resourceId ? [resourceId] : undefined,
        })
        .promise()

      nextToken = describeInternetGateways.NextToken

      if (describeInternetGateways.InternetGateways) {
        igws = igws.concat(describeInternetGateways.InternetGateways)
      }
    } while (nextToken)

    return igws
  }

  listBuckets = async () => {
    /** no need to define a region, s3 endpoint is global */
    const s3 = new this.AWS.S3(this.options)
    let buckets: Bucket[] = []

    const listBuckets = await s3.listBuckets().promise()

    if (listBuckets.Buckets) {
      buckets = buckets.concat(listBuckets.Buckets)
    }

    return buckets
  }

  describeSecurityGroups = async (region: string, resourceId?: string) => {
    const options = this.getOptions()
    options.region = region

    const ec2 = new this.AWS.EC2(options)

    let nextToken: string | undefined

    let groups: SecurityGroup[] = []

    do {
      const describeSecurityGroups = await ec2
        .describeSecurityGroups({
          NextToken: nextToken,
          GroupIds: resourceId ? [resourceId] : undefined,
        })
        .promise()
      nextToken = describeSecurityGroups.NextToken
      if (describeSecurityGroups.SecurityGroups) {
        groups = groups.concat(describeSecurityGroups.SecurityGroups)
      }
    } while (nextToken)

    return groups
  }

  describeVolumes = async (region: string, resourceId?: string) => {
    const options = this.getOptions()
    options.region = region

    const ec2 = new this.AWS.EC2(options)

    let nextToken: string | undefined

    let volumes: Volume[] = []

    do {
      const describeVolumes = await ec2
        .describeVolumes({
          NextToken: nextToken,
          VolumeIds: resourceId ? [resourceId] : undefined,
        })
        .promise()

      nextToken = describeVolumes.NextToken

      if (describeVolumes.Volumes) {
        volumes = volumes.concat(describeVolumes.Volumes)
      }
    } while (nextToken)

    return volumes
  }

  listKeys = async (region: string) => {
    const options = this.getOptions()
    options.region = region

    const kms = new this.AWS.KMS(options)

    let marker: string | undefined

    let keys: KeyListEntry[] = []

    do {
      const listKeys = await kms
        .listKeys({
          Marker: marker,
        })
        .promise()
      marker = listKeys.NextMarker
      if (listKeys.Keys) {
        keys = keys.concat(listKeys.Keys)
      }
    } while (marker)

    return keys
  }

  listUsers = async () => {
    /** no need to set a region iam is global */
    const iam = new this.AWS.IAM(this.options)

    let users: User[] = []

    let marker: string | undefined

    do {
      const listUsers = await iam
        .listUsers({
          Marker: marker,
        })
        .promise()

      marker = listUsers.Marker

      if (listUsers.Users) {
        users = users.concat(listUsers.Users)
      }
    } while (marker)

    return users
  }

  listTopics = async (region: string) => {
    const options = this.getOptions()
    options.region = region

    const sns = new this.AWS.SNS(options)

    let nextToken: string | undefined

    let topics: Topic[] = []

    do {
      const listTopics = await sns
        .listTopics({
          NextToken: nextToken,
        })
        .promise()
      nextToken = listTopics.NextToken
      if (listTopics.Topics) {
        topics = topics.concat(listTopics.Topics)
      }
    } while (nextToken)

    return topics
  }

  getKeyMetadata = async (keyArn?: string, region?: string) => {
    const options = this.getOptions()
    const kms = new this.AWS.KMS(options)

    /** if we haven't populated a list of key IDs from within this account */
    this.keyMetaData = []

    if (keyArn) {
      assert(region, 'must provide a region this key lives in')
      const describeKey = await kms
        .describeKey({
          KeyId: keyArn,
        })
        .promise()
      if (describeKey.KeyMetadata) {
        this.keyMetaData = this.keyMetaData.concat(describeKey.KeyMetadata)
      }
    } else {
      const regions = await this.describeRegions()

      for (const region of regions) {
        this.spinner.text = `${region} - key inventory`
        options.region = region
        const keys = await this.listKeys(region)
        for (const key of keys) {
          assert(key.KeyArn, 'kms key missing arn')
          const describeKey = await kms
            .describeKey({
              KeyId: key.KeyArn,
            })
            .promise()
          if (describeKey.KeyMetadata) {
            this.keyMetaData = this.keyMetaData.concat(describeKey.KeyMetadata)
          }
        }
      }
    }
  }

  findKey = async (keyArn: string, region: string) => {
    /** metadata array is undefined on class init, populate it as needed */
    if (this.keyMetaData === undefined) {
      await this.getKeyMetadata(keyArn, region)
    }

    assert(this.keyMetaData, 'key metadata not set')

    return this.keyMetaData.find((metaData) => metaData.Arn === keyArn)
  }

  isKeyTrusted = async (keyArn: string, type: 'aws' | 'cmk' = 'aws') => {
    const matched = await this.findKey(keyArn)
    let trusted: 'UNKNOWN' | 'TRUSTED' | 'WARNING' = 'UNKNOWN'
    if (matched) {
      if (type === 'aws') {
        trusted = 'TRUSTED'
      } else if (type === 'cmk') {
        /**
         * any encryption is better then no encryption, set to warning and
         * override to TRUSTED if this is in fact a CMK
         */
        trusted = 'WARNING'
        if (matched.KeyManager === 'CUSTOMER') {
          trusted = 'TRUSTED'
        }
      }
    }

    return trusted
  }

  /**
   * check the specified key against what?
   * what lvl of key is it?
   * is it a cmk?  If so is it trusted?
   * what is a trusted cmdk?
   *   any cmk "in" this account or part of a trusted account array
   */
}
