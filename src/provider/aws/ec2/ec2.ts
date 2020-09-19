import { Argv } from 'yargs'

export const command = 'ec2'
export const desc = 'elastic cloud compute (ec2)'

export const builder = (yargs: Argv) => {
  return yargs.commandDir('sg')
}
