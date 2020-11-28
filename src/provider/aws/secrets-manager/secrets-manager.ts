import { Argv } from 'yargs'

export const command = 'sm'
export const desc = 'Secrets Manager'

const opts = {
  exclude: /.*.test.js/,
}

export const builder = (yargs: Argv) => {
  return yargs.commandDir('cmds', opts).demandCommand(1)
}
