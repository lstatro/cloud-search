import { Argv } from 'yargs'

export const command = 'users'
export const desc = 'IAM user rules'

export const builder = (yargs: Argv) => {
  return yargs.commandDir('cmds').demandCommand(1)
}
