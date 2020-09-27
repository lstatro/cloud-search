import { Argv } from 'yargs'

export const command = 'ebs'
export const desc = 'Elastic Block Store (EBS)'

export const builder = (yargs: Argv) => {
  return yargs.commandDir('cmds').demandCommand(1)
}
