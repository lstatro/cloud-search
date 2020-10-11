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

• Scans looking for CMK as the source key type will report resources  using AWS 
  managed keys for encryption as 'WARNING' instead of 'FAIL'.  This was done 
  intentionally as some level of encryption is better then no encryption.

• All keys in all regions regardless of the requested region have metadata read
  into the system.  This is because keys may encrypt resources in any region
  regardless of the region the key resides.

********************************************************************************
`

export const builder = (yargs: Argv) => {
  return yargs
    .commandDir('./aws/ec2')
    .commandDir('./aws/s3')
    .commandDir('./aws/iam')
    .commandDir('./aws/sns')
    .commandDir('./aws/sqs')
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
