import { Argv } from 'yargs'

export const command = 'sg'
export const desc = 'ec2 security groups'

export const builder = (yargs: Argv) => {
  return yargs.commandDir('cmds').demandCommand(1)
}
