import { Argv } from 'yargs'

export const command = 'logs'
export const desc = 'CloudWatch logs'

const opts = {
  exclude: /.*.test.js/,
}

export const builder = (yargs: Argv) => {
  return yargs.commandDir('cmds', opts).demandCommand(1)
}
