import { Argv } from 'yargs'

export const command = 'roles'
export const desc = 'IAM role scans'

export const builder = (yargs: Argv) => {
  return yargs.commandDir('cmds').demandCommand(1)
}
