import { Argv } from 'yargs'

export const command = 's3 [args]'
export const desc = 'simple storage service (s3)'

export const builder = (yargs: Argv) => {
  return yargs.commandDir('cmds').demandCommand(1)
}
