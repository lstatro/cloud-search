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
}
