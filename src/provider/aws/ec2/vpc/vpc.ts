import { Argv } from 'yargs'

export const command = 'vpc'
export const desc = 'virtual private cloud (VPC)'

export const builder = (yargs: Argv) => {
  return yargs.commandDir('cmds').demandCommand(1)
}
