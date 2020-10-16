import { Argv } from 'yargs'

export const command = 'vpc'
export const desc = 'virtual private cloud (VPC)'

const opts = {
  exclude: /.*.test.js/,
}

export const builder = (yargs: Argv) => {
  return yargs.commandDir('cmds', opts).demandCommand(1)
}
