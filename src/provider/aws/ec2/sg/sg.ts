import { Argv } from 'yargs'

export const command = 'sg'
export const desc = 'ec2 security groups'

const opts = {
  exclude: /.*.test.js/,
}

export const builder = (yargs: Argv) => {
  return yargs.commandDir('cmds', opts).demandCommand(1)
}
