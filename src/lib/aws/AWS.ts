import { AWSClientOptionsInterface } from 'cloud-search'
import _AWS from 'aws-sdk'
import Provider from '../Provider'

import assert from 'assert'
import { Bucket } from 'aws-sdk/clients/s3'
import {
  InternetGateway,
  SecurityGroup,
  Snapshot,
  Volume,
} from 'aws-sdk/clients/ec2'
import { KeyListEntry, KeyMetadata } from 'aws-sdk/clients/kms'
import { Role, User } from 'aws-sdk/clients/iam'
import { Topic } from 'aws-sdk/clients/sns'
import { QueueUrlList } from 'aws-sdk/clients/sqs'
import { DBCluster, DBInstance } from 'aws-sdk/clients/rds'

interface AWSParamsInterface {
  profile: string
  rule: string
  resourceId?: string
  region: string
}

interface ScanInterface {
  region?: string
  resourceId?: string
}

interface KeyCacheInterface extends KeyMetadata {
  givenKeyId?: string
}

interface AuditInterface {
  [key: string]: unknown
  resourceId: unknown
  region?: string
}

export default abstract class AwsService extends Provider {
  abstract service: string

  options: AWSClientOptionsInterface

  region: string
  regions: string[] = []
  global = false
  AWS = _AWS
  keyMetaData: KeyCacheInterface[] = []
  profile?: string
  resourceId?: string

  constructor(params: AWSParamsInterface) {
    super(params.rule)

    this.region = params.region
    this.profile = params.profile
    this.resourceId = params.resourceId

    this.AWS.config.update({
      maxRetries: 20,
    })

    this.options = this.getOptions()
  }

  abstract async scan(params: ScanInterface): Promise<void>

  abstract audit(params: AuditInterface): Promise<void>

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
        assert(
          this.region !== 'all',
          'must provide a region for a resource specific scan'
        )
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
      /** do nothing, just move on to checking all regions for the key */
    }

    const regions = await this.describeRegions()

    for (const _region of regions) {
      try {
        this.spinner.text = `${_region} - key inventory`

        options.region = _region

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
        /** do nothing, just keep checking the next region */
      }
    }

    /**
     * if we make it out of the region loop w/o finding the key it doesn't
     * exist
     */
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

  listQueues = async (region: string) => {
    const options = this.getOptions()
    options.region = region

    const sqs = new this.AWS.SQS(options)

    let nextToken: string | undefined

    let queues: QueueUrlList = []

    do {
      const listQueues = await sqs
        .listQueues({
          NextToken: nextToken,
        })
        .promise()
      nextToken = listQueues.NextToken
      if (listQueues.QueueUrls) {
        queues = queues.concat(listQueues.QueueUrls)
      }
    } while (nextToken)

    return queues
  }

  listSnapshots = async (region: string) => {
    const options = this.getOptions()
    options.region = region

    const ec2 = new this.AWS.EC2(options)

    let nextToken: string | undefined

    let snapshots: Snapshot[] = []

    do {
      const describeSnapshots = await ec2
        .describeSnapshots({
          NextToken: nextToken,
          OwnerIds: ['self'],
        })
        .promise()
      nextToken = describeSnapshots.NextToken
      if (describeSnapshots.Snapshots) {
        snapshots = snapshots.concat(describeSnapshots.Snapshots)
      }
    } while (nextToken)

    return snapshots
  }

  listRoles = async () => {
    /** no need to set a region iam is global */
    const iam = new this.AWS.IAM(this.options)

    let roles: Role[] = []

    let marker: string | undefined

    do {
      const listRoles = await iam
        .listRoles({
          Marker: marker,
        })
        .promise()

      marker = listRoles.Marker

      if (listRoles.Roles) {
        roles = roles.concat(listRoles.Roles)
      }
    } while (marker)

    return roles
  }

  listDBInstances = async (region: string, dBInstanceIdentifier?: string) => {
    const options = this.getOptions()
    options.region = region

    const rds = new this.AWS.RDS(options)

    let marker: string | undefined

    let dbInstances: DBInstance[] = []

    do {
      const describeDBInstances = await rds
        .describeDBInstances({
          DBInstanceIdentifier: dBInstanceIdentifier,
          Marker: marker,
        })
        .promise()
      marker = describeDBInstances.Marker
      if (describeDBInstances.DBInstances) {
        dbInstances = dbInstances.concat(describeDBInstances.DBInstances)
      }
    } while (marker)

    return dbInstances
  }

  listDBClusters = async (region: string, dbClusterIdentifier?: string) => {
    const options = this.getOptions()
    options.region = region

    const rds = new this.AWS.RDS(options)

    let marker: string | undefined

    let dbClusters: DBCluster[] = []

    do {
      const describeDBClusters = await rds
        .describeDBClusters({
          DBClusterIdentifier: dbClusterIdentifier,
          Marker: marker,
        })
        .promise()
      marker = describeDBClusters.Marker
      if (describeDBClusters.DBClusters) {
        dbClusters = dbClusters.concat(describeDBClusters.DBClusters)
      }
    } while (marker)

    return dbClusters
  }
}
