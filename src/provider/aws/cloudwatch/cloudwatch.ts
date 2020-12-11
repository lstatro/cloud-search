import { Argv } from 'yargs'

export const command = 'cloudwatch'
export const desc = 'CloudWatch'

const opts = {
  exclude: /.*.test.js/,
}

export const builder = (yargs: Argv) => {
  return yargs.commandDir('logs', opts).demandCommand(1)
}
