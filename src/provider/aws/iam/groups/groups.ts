import { Argv } from 'yargs'

export const command = 'groups'
export const desc = 'IAM user group rules'

const opts = {
  exclude: /.*.test.js/,
}

export const builder = (yargs: Argv) => {
  return yargs.commandDir('cmds', opts).demandCommand(1)
}
