import { Argv } from 'yargs'

export const command = 'roles'
export const desc = 'IAM role scans'

const opts = {
  exclude: /.*.test.js/,
}

export const builder = (yargs: Argv) => {
  return yargs.commandDir('cmds', opts).demandCommand(1)
}
