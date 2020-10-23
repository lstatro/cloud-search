import { CommandBuilder } from 'yargs'
import {
  AWSClientOptionsInterface,
  AWSParamsInterface,
  KeyType,
} from 'cloud-search'
import { Bucket } from 'aws-sdk/clients/s3'
import {
  InternetGateway,
  SecurityGroup,
  Snapshot,
  Volume,
} from 'aws-sdk/clients/ec2'
import { KeyMetadata, KeyListEntry } from 'aws-sdk/clients/kms'
import { Role, User } from 'aws-sdk/clients/iam'
import { Topic } from 'aws-sdk/clients/sns'
import { QueueUrlList } from 'aws-sdk/clients/sqs'
import { DBCluster, DBInstance } from 'aws-sdk/clients/rds'
import _AWS from 'aws-sdk'
import Provider from '../Provider'
import assert from 'assert'
import { TrailInfo } from 'aws-sdk/clients/cloudtrail'
import { CacheCluster } from 'aws-sdk/clients/elasticache'

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

  options: AWSClientOptionsInterface

  region: string
  regions: string[] = []
  global = false
  AWS = _AWS
  keyMetaData: KeyCacheInterface[] = []
  profile?: string
  resourceId?: string
  keyType?: KeyType

  constructor(params: AWSParamsInterface) {
    super(params.rule, params.verbosity)

    this.region = params.region
    this.profile = params.profile
    this.resourceId = params.resourceId

    this.AWS.config.update({
      maxRetries: 20,
    })

    this.keyType = params.keyType

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

  listInternetGateways = async (region: string, resourceId?: string) => {
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

  listSecurityGroups = async (region: string, resourceId?: string) => {
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

  listVolumes = async (region: string, resourceId?: string) => {
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

  listSnapshots = async (region: string, resourceId?: string) => {
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
          SnapshotIds: resourceId ? [resourceId] : undefined,
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

  listTrails = async (region: string) => {
    const options = this.getOptions()
    options.region = region

    const cloudtrail = new this.AWS.CloudTrail(options)

    let nextToken: string | undefined

    const trails: TrailInfo[] = []

    do {
      const listTrails = await cloudtrail
        .listTrails({
          NextToken: nextToken,
        })
        .promise()
      nextToken = listTrails.NextToken
      if (listTrails.Trails) {
        for (const trail of listTrails.Trails) {
          /**
           * Weird, but global trails are returned in every listTrails api call.
           * This is a little misleading as technically CT isn't a global service.
           * To combat this oddness, we're going to only validate trails in the
           * target region.  If it's global and it's not in this region we just
           * ignore it.  If its then we'll audit it.  This allows us to also audit
           * regional trails as false in all regions.  This used to be a global
           * rules but the weirdness bit us in the long run.
           */
          if (trail.HomeRegion === region) {
            trails.push(trail)
          }
        }
      }
    } while (nextToken)

    return trails
  }

  listElastiCacheClusters = async (region: string, resourceId?: string) => {
    const options = this.getOptions()
    options.region = region

    const ec = new this.AWS.ElastiCache(options)

    let marker: string | undefined

    let cacheCluster: CacheCluster[] = []

    do {
      const describeCacheClusters = await ec
        .describeCacheClusters({
          CacheClusterId: resourceId,
          Marker: marker,
        })
        .promise()
      marker = describeCacheClusters.Marker
      if (describeCacheClusters.CacheClusters) {
        cacheCluster = cacheCluster.concat(describeCacheClusters.CacheClusters)
      }
    } while (marker)

    return cacheCluster
  }

  // listElastiCacheReplicationGroups = async (
  //   region: string,
  //   resourceId?: string
  // ) => {
  //   const options = this.getOptions()
  //   options.region = region

  //   const ec = new this.AWS.ElastiCache(options)

  //   let marker: string | undefined

  //   // let cacheCluster: CacheCluster[] = []
  //   let replicationGroup: ReplicationGroup[] = []

  //   do {
  //     const describeCacheClusters = await ec
  //       .describeReplicationGroups({
  //         ReplicationGroupId: resourceId,
  //         // CacheClusterId: resourceId,
  //         Marker: marker,
  //       })
  //       .promise()
  //     marker = describeCacheClusters.Marker
  //     if (describeCacheClusters.ReplicationGroups) {
  //       replicationGroup = replicationGroup.concat(
  //         describeCacheClusters.ReplicationGroups
  //       )
  //     }
  //   } while (marker)

  //   return replicationGroup
  // }
}
