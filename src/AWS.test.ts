import { expect } from 'chai'
import {
  cloudtrail,
  dynamodb,
  ec2,
  elasticache,
  guardduty,
  iam,
  kms,
  neptune,
  rds,
  s3,
  sns,
  sqs,
  emr,
} from './AWS'

describe('AWS module', () => {
  it('should have all cloudtrail rules', () => {
    const keys = Object.keys(cloudtrail)
    expect(cloudtrail.MultiRegionTrailEnabled.name).to.eql(
      'MultiRegionTrailEnabled'
    )
    expect(cloudtrail.TrailEncrypted.name).to.eql('TrailEncrypted')
    expect(cloudtrail.TrailEvents.name).to.eql('TrailEvents')

    expect(keys).to.eql([
      'MultiRegionTrailEnabled',
      'TrailEncrypted',
      'TrailEvents',
    ])
  })

  it('should have all dynamodb rules', () => {
    const keys = Object.keys(dynamodb)
    expect(dynamodb.EncryptionAtRest.name).to.eql('EncryptionAtRest')
    expect(keys).to.eql(['EncryptionAtRest'])
  })

  describe('ec2', () => {
    it('should have all sub rules', () => {
      const keys = Object.keys(ec2)
      expect(keys).to.eql(['ebs', 'sg', 'vpc', 'xlb'])
    })

    it('should have all ebs rules', () => {
      const keys = Object.keys(ec2.ebs)
      expect(ec2.ebs.SnapshotEncrypted.name).to.eql('SnapshotEncrypted')
      expect(ec2.ebs.SnapshotPublic.name).to.eql('SnapshotPublic')
      expect(ec2.ebs.VolumeEncrypted.name).to.eql('VolumeEncrypted')
      expect(keys).to.eql([
        'SnapshotEncrypted',
        'SnapshotPublic',
        'VolumeEncrypted',
      ])
    })

    it('should have all sg rules', () => {
      const keys = Object.keys(ec2.sg)
      expect(ec2.sg.PublicPermission.name).to.eql('PublicPermission')
      expect(keys).to.eql(['PublicPermission'])
    })

    it('should have all vpc rules', () => {
      const keys = Object.keys(ec2.vpc)
      expect(ec2.vpc.IgwAttachedToVpc.name).to.eql('IgwAttachedToVpc')
      expect(keys).to.eql(['IgwAttachedToVpc'])
    })

    it('should have all xlb rules', () => {
      const keys = Object.keys(ec2.xlb)
      expect(ec2.xlb.Elbv2AccessLogsEnabled.name).to.eql(
        'Elbv2AccessLogsEnabled'
      )
      expect(ec2.xlb.AlbWafEnabled.name).to.eql('AlbWafEnabled')
      expect(ec2.xlb.ElbAccessLogsEnabled.name).to.eql('ElbAccessLogsEnabled')
      expect(ec2.xlb.ElbDesyncMode.name).to.eql('ElbDesyncMode')
      expect(keys).to.eql([
        'Elbv2AccessLogsEnabled',
        'AlbWafEnabled',
        'ElbAccessLogsEnabled',
        'ElbDesyncMode',
      ])
    })
  })

  it('should have all elasticache rules', () => {
    const keys = Object.keys(elasticache)
    expect(elasticache.EncryptionAtRest.name).to.eql('EncryptionAtRest')
    expect(elasticache.TransitEncryptionEnabled.name).to.eql(
      'TransitEncryptionEnabled'
    )
    expect(keys).to.eql(['EncryptionAtRest', 'TransitEncryptionEnabled'])
  })

  it('should have all guardduty rules', () => {
    const keys = Object.keys(guardduty)
    expect(guardduty.DetectorExists.name).to.eql('DetectorExists')
    expect(guardduty.DetectorDataSources.name).to.eql('DetectorDataSources')
    expect(guardduty.DetectorEnabled.name).to.eql('DetectorEnabled')
    expect(keys).to.eql([
      'DetectorExists',
      'DetectorDataSources',
      'DetectorEnabled',
    ])
  })

  describe('iam', () => {
    it('should have all sub rules', () => {
      const keys = Object.keys(iam)
      expect(keys).to.eql(['groups', 'roles', 'users'])
    })

    it('should have group rules', () => {
      const keys = Object.keys(iam.groups)
      expect(iam.groups.HasManagedAdmin.name).to.eql('HasManagedAdmin')
      expect(keys).to.eql(['HasManagedAdmin'])
    })

    it('should have role rules', () => {
      const keys = Object.keys(iam.roles)
      expect(iam.roles.HasManagedAdmin.name).to.eql('HasManagedAdmin')
      expect(iam.roles.PublicRole.name).to.eql('PublicRole')
      expect(keys).to.eql(['HasManagedAdmin', 'PublicRole'])
    })

    it('should have user rules', () => {
      const keys = Object.keys(iam.users)
      expect(iam.users.HasManagedAdmin.name).to.eql('HasManagedAdmin')
      expect(iam.users.MaxKeyAge.name).to.eql('MaxKeyAge')
      expect(iam.users.PasswordAge.name).to.eql('PasswordAge')
      expect(iam.users.RootUser.name).to.eql('RootUser')
      expect(iam.users.UserMfaEnabled.name).to.eql('UserMfaEnabled')
      expect(keys).to.eql([
        'HasManagedAdmin',
        'MaxKeyAge',
        'PasswordAge',
        'RootUser',
        'UserMfaEnabled',
      ])
    })
  })

  it('should have all kms rules', () => {
    const keys = Object.keys(kms)
    expect(kms.KeyRotationEnabled.name).to.eql('KeyRotationEnabled')
    expect(keys).to.eql(['KeyRotationEnabled'])
  })

  it('should have all neptune rules', () => {
    const keys = Object.keys(neptune)
    expect(neptune.ClusterEncrypted.name).to.eql('ClusterEncrypted')
    expect(neptune.InstanceEncrypted.name).to.eql('InstanceEncrypted')
    expect(keys).to.eql(['ClusterEncrypted', 'InstanceEncrypted'])
  })

  it('should have all rds rules', () => {
    const keys = Object.keys(rds)
    expect(rds.ClusterEncrypted.name).to.eql('ClusterEncrypted')
    expect(rds.InstanceEncrypted.name).to.eql('InstanceEncrypted')
    expect(rds.PublicInstance.name).to.eql('PublicInstance')
    expect(keys).to.eql([
      'ClusterEncrypted',
      'InstanceEncrypted',
      'PublicInstance',
    ])
  })

  it('should have all s3 rules', () => {
    const keys = Object.keys(s3)
    expect(s3.BucketEncryption.name).to.eql('BucketEncryption')
    expect(s3.PublicAccessBlocks.name).to.eql('PublicAccessBlocks')
    expect(keys).to.eql(['BucketEncryption', 'PublicAccessBlocks'])
  })

  it('should have all sns rules', () => {
    const keys = Object.keys(sns)
    expect(sns.TopicEncrypted.name).to.eql('TopicEncrypted')
    expect(keys).to.eql(['TopicEncrypted'])
  })

  it('should have all sqs rules', () => {
    const keys = Object.keys(sqs)
    expect(sqs.QueueEncrypted.name).to.eql('QueueEncrypted')
    expect(keys).to.eql(['QueueEncrypted'])
  })

  it('should have all emr rules', () => {
    const keys = Object.keys(emr)
    expect(emr.EmrCluster.name).to.eql('EmrCluster')
    expect(emr.SecurityConfigSetting.name).to.eql('SecurityConfigSetting')
    expect(keys).to.eql(['EmrCluster', 'SecurityConfigSetting'])
  })
})
