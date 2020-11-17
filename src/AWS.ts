import { MultiRegionTrailEnabled } from './provider/aws/cloudtrail/cmds/multiRegionTrailEnabled'
import { TrailEncrypted } from './provider/aws/cloudtrail/cmds/trailEncrypted'
import { TrailEvents } from './provider/aws/cloudtrail/cmds/trailEvents'
export const cloudtrail = {
  MultiRegionTrailEnabled,
  TrailEncrypted,
  TrailEvents,
}

import { EncryptionAtRest as ddb_EncryptionAtRest } from './provider/aws/dynamodb/cmds/encryptionAtRest'
export const dynamodb = {
  EncryptionAtRest: ddb_EncryptionAtRest,
}

import { SnapshotEncrypted } from './provider/aws/ec2/ebs/cmds/snapshotEncrypted'
import { SnapshotPublic } from './provider/aws/ec2/ebs/cmds/snapshotPublic'
import { VolumeEncrypted } from './provider/aws/ec2/ebs/cmds/volumeEncrypted'
import { PublicPermission } from './provider/aws/ec2/sg/cmds/publicPermission'
import { IgwAttachedToVpc } from './provider/aws/ec2/vpc/cmds/igwAttachedToVpc'
import { Elbv2AccessLogsEnabled } from './provider/aws/ec2/xlb/cmds/elbv2AccessLogsEnabled'
import { AlbWafEnabled } from './provider/aws/ec2/xlb/cmds/albWafEnabled'
import { ElbAccessLogsEnabled } from './provider/aws/ec2/xlb/cmds/elbAccessLogsEnabled'
import { ElbDesyncMode } from './provider/aws/ec2/xlb/cmds/elbDesyncMode'
export const ec2 = {
  ebs: {
    SnapshotEncrypted,
    SnapshotPublic,
    VolumeEncrypted,
  },
  sg: {
    PublicPermission,
  },
  vpc: {
    IgwAttachedToVpc,
  },
  xlb: {
    Elbv2AccessLogsEnabled,
    AlbWafEnabled,
    ElbAccessLogsEnabled,
    ElbDesyncMode,
  },
}

import { EncryptionAtRest as ec_EncryptionAtRest } from './provider/aws/elasticache/cmds/encryptionAtRest'
import { TransitEncryptionEnabled } from './provider/aws/elasticache/cmds/transitEncryptionEnabled'
export const elasticache = {
  EncryptionAtRest: ec_EncryptionAtRest,
  TransitEncryptionEnabled,
}

import { DetectorExists } from './provider/aws/guardduty/cmds/detectorExists'
import { DetectorDataSources } from './provider/aws/guardduty/cmds/detectorDataSources'
import { DetectorEnabled } from './provider/aws/guardduty/cmds/detectorEnabled'
export const guardduty = {
  DetectorExists,
  DetectorDataSources,
  DetectorEnabled,
}

import { HasManagedAdmin as groups_HasManagedAdmin } from './provider/aws/iam/groups/cmds/hasManagedAdmin'
import { HasManagedAdmin as roles_HasManagedAdmin } from './provider/aws/iam/roles/cmds/hasManagedAdmin'
import { PublicRole } from './provider/aws/iam/roles/cmds/publicRole'
import { HasManagedAdmin as users_HasManagedAdmin } from './provider/aws/iam/users/cmds/hasManagedAdmin'
import { MaxKeyAge } from './provider/aws/iam/users/cmds/maxKeyAge'
import { PasswordAge } from './provider/aws/iam/users/cmds/passwordAge'
export const iam = {
  groups: {
    HasManagedAdmin: groups_HasManagedAdmin,
  },
  roles: {
    HasManagedAdmin: roles_HasManagedAdmin,
    PublicRole,
  },
  users: {
    HasManagedAdmin: users_HasManagedAdmin,
    MaxKeyAge,
    PasswordAge,
  },
}

import { KeyRotationEnabled } from './provider/aws/kms/cmds/keyRotationEnabled'
export const kms = {
  KeyRotationEnabled,
}

import { ClusterEncrypted as neptune_ClusterEncrypted } from './provider/aws/neptune/clusters/clusterEncrypted'
import { InstanceEncrypted as neptune_InstanceEncrypted } from './provider/aws/neptune/instances/instanceEncrypted'
export const neptune = {
  ClusterEncrypted: neptune_ClusterEncrypted,
  InstanceEncrypted: neptune_InstanceEncrypted,
}

import { ClusterEncrypted as rds_ClusterEncrypted } from './provider/aws/rds/clusters/clusterEncrypted'
import { InstanceEncrypted } from './provider/aws/rds/instances/instanceEncrypted'
import { PublicInstance } from './provider/aws/rds/instances/publicInstance'
export const rds = {
  ClusterEncrypted: rds_ClusterEncrypted,
  InstanceEncrypted,
  PublicInstance,
}

import { BucketEncryption } from './provider/aws/s3/cmds/bucketEncryption'
import { PublicAccessBlocks } from './provider/aws/s3/cmds/publicAccessBlocks'
export const s3 = {
  BucketEncryption,
  PublicAccessBlocks,
}

import { TopicEncrypted } from './provider/aws/sns/cmds/topicEncrypted'
export const sns = {
  TopicEncrypted,
}

import { QueueEncrypted } from './provider/aws/sqs/cmds/queueEncrypted'
export const sqs = {
  QueueEncrypted,
}
