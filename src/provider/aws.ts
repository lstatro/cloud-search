import { Argv } from 'yargs'

export const command = 'aws'
export const desc = 'aws cloud provider'

export const builder = (yargs: Argv) => {
  return yargs
    .commandDir('./aws/ec2')
    .commandDir('./aws/s3')
    .commandDir('./aws/iam')
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
    .option('domain', {
      alias: 'd',
      describe: 'public or us-gov cloud',
      type: 'string',
      choices: ['pub', 'gov'],
      default: 'pub',
      demandOption: true,
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
}
