import { Argv } from 'yargs'

export const command = 'ec2'
export const desc = 'Elastic Cloud Compute (EC2)'

const opts = {
  exclude: /.*.test.js/,
}

export const builder = (yargs: Argv) => {
  return yargs
    .commandDir('sg', opts)
    .commandDir('vpc', opts)
    .commandDir('ebs', opts)
    .demandCommand(1)
}
