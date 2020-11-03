import { Argv } from 'yargs'

export const command = 'aws'
export const desc = 'aws cloud provider'

const epilogue = `
********************************** Regions *************************************

• When scanning a specific resource (-i) specify the region that resource lives
  in.  For global services such as IAM or S3, use any valid region.

********************************** Encryption **********************************

• Encryption keys in AWS comes in two general flavors, AWS managed and customer
  managed (CMK).  We view CMK's as "more secure" then AWS managed keys as they
  support more levels of rotation.  

• Scans looking for CMK as the source key type will report resources using AWS 
  managed keys for encryption as 'WARNING' instead of 'FAIL'.  This was done 
  intentionally as some level of encryption is better then no encryption.

• If a key used to encrypt an object no longer exists it is possible that the
  resourceId is encrypted, but scans will still report FAIL.  This is because the
  scan is attempting to link the key with something known.  This happens when
  the key used to encrypt the object is shared from another account, and that
  source account has removed access to the target account.  This also
  effectively breaks the resource making it unusable.

************************* Policy and Access Rights *****************************

• IAM inline, managed, and group policy rights are all unique.  Many of the
  rules that check for permissions do so in a vacuum.  Meaning, if a user has 
  admin directly applied, the group policy check may return OK,  where as the 
  user admin check will return FAIL.  This was done purposely as it allow finer 
  view over how a user got the targeted rights.  

  This also means that when looking for resources that have admin more then one
  scan is necessary.  For example when looking for users with admin it is
  necessary to check the user, the user's, groups, and any inline policy they
  have.

********************************************************************************
`

const opts = {
  exclude: /.*.test.js/,
}

export const builder = (yargs: Argv) => {
  return yargs
    .commandDir('./aws/ec2', opts)
    .commandDir('./aws/s3', opts)
    .commandDir('./aws/iam', opts)
    .commandDir('./aws/sns', opts)
    .commandDir('./aws/sqs', opts)
    .commandDir('./aws/rds', opts)
    .commandDir('./aws/kms', opts)
    .commandDir('./aws/cloudtrail', opts)
    .commandDir('./aws/elasticache', opts)
    .commandDir('./aws/guardduty', opts)
    .commandDir('./aws/neptune', opts)
    .commandDir('./aws/dynamo', opts)
    .demandCommand(1)
    .option('region', {
      alias: 'r',
      describe: 'aws region name',
      type: 'string',
      default: 'all',
    })
    .option('profile', {
      alias: 'p',
      describe: 'aws profile name',
      type: 'string',
    })
    .option('resourceId', {
      alias: 'i',
      describe: 'resource id',
      type: 'string',
    })
    .example([
      [
        'aws s3 PublicAccessBlocks -p lolComplianceProfile',
        'runs all four public access block checks against all buckets',
      ],
      [
        'aws ec2 vpc IgwAttachedToVpc -r us-east-1',
        'checks all VPCs in us-east-1 for an attached IGW',
      ],
    ])
    .epilogue(epilogue)
}
