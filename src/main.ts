export const AWS = {
  cloudtrail: {
    MultiRegionTrailEnabled: require('./provider/aws/cloudtrail/cmds/multiRegionTrailEnabled'),
    TrailEncrypted: require('./provider/aws/cloudtrail/cmds/trailEncrypted'),
    TrailEvents: require('./provider/aws/cloudtrail/cmds/trailEvents'),
  },
  ec2: {
    ebs: {
      SnapshotEncrypted: require('./provider/aws/ec2/ebs/cmds/snapshotEncrypted'),
      SnapshotPublic: require('./provider/aws/ec2/ebs/cmds/snapshotPublic'),
      VolumeEncrypted: require('./provider/aws/ec2/ebs/cmds/volumeEncrypted'),
    },
    sg: {
      PublicPermission: require('./provider/aws/ec2/sg/cmds/publicPermission'),
    },
    vpc: {
      IgwAttached: require('./provider/aws/ec2/vpc/cmds/igwAttached'),
    },
  },
  elasticache: {
    EncryptionAtRest: require('./provider/aws/elasticache/cmds/encryptionAtRest'),
    TransitEncryptionEnabled: require('./provider/aws/elasticache/cmds/transitEncryptionEnabled'),
  },
  guardduty: {
    DetectorDataSources: require('./provider/aws/guardduty/cmds/detectorDataSources'),
    DetectorEnabled: require('./provider/aws/guardduty/cmds/detectorEnabled'),
    detectorExists: require('./provider/aws/guardduty/cmds/detectorExists'),
    DetectorSourceCloudTrail: require('./provider/aws/guardduty/cmds/detectorSourceCloudTrail'),
    DetectorSourceDnsLogs: require('./provider/aws/guardduty/cmds/detectorSourceDnsLogs'),
    DetectorSourceFlowLogs: require('./provider/aws/guardduty/cmds/detectorSourceFlowLogs'),
    DetectorSourceS3Logs: require('./provider/aws/guardduty/cmds/detectorSourceS3Logs'),
  },
  iam: {
    groups: {
      HasManagedAdmin: require('./provider/aws/iam/groups/cmds/hasManagedAdmin'),
    },
    roles: {
      HasManagedAdmin: require('./provider/aws/iam/roles/cmds/hasManagedAdmin'),
      PublicRole: require('./provider/aws/iam/roles/cmds/publicRole'),
    },
    users: {
      HasManagedAdmin: require('./provider/aws/iam/users/cmds/hasManagedAdmin'),
      MaxKeyAge: require('./provider/aws/iam/users/cmds/maxKeyAge'),
      PasswordAge: require('./provider/aws/iam/users/cmds/passwordAge'),
    },
  },
  kms: {
    KeyRotationEnabled: require('./provider/aws/kms/cmds/keyRotationEnabled'),
  },
  rds: {
    ClusterEncrypted: require('./provider/aws/rds/clusters/clusterEncrypted'),
    InstanceEncrypted: require('./provider/aws/rds/instances/instanceEncrypted'),
    PublicInstance: require('./provider/aws/rds/instances/publicInstance'),
  },
  s3: {
    BlockPublicAcls: require('./provider/aws/s3/cmds/blockPublicAcls'),
    BlockPublicPolicy: require('./provider/aws/s3/cmds/blockPublicPolicy'),
    IgnorePublicAcls: require('./provider/aws/s3/cmds/ignorePublicAcls'),
    RestrictPublicBuckets: require('./provider/aws/s3/cmds/restrictPublicBuckets'),
    BucketEncryption: require('./provider/aws/s3/cmds/bucketEncryption'),
  },
  sns: {
    TopicEncrypted: require('./provider/aws/sns/cmds/topicEncrypted'),
  },
  sqs: {
    QueueEncrypted: require('./provider/aws/sqs/cmds/queueEncrypted'),
  },
  neptune: {
    ClusterEncrypted: require('./provider/aws/neptune/clusters/clusterEncrypted'),
    InstanceEncrypted: require('./provider/aws/neptune/instances/instanceEncrypted'),
  },
  dynamo: {
    EncryptionAtRest: require('./provider/aws/dynamo/cmds/encryptionAtRest'),
  },
}
