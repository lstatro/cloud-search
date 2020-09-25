import { Argv } from 'yargs'

export const command = 'iam'
export const desc = 'Identity and Access Management (IAM)'

export const builder = (yargs: Argv) => {
  return yargs.commandDir('users').demandCommand(1)
}
