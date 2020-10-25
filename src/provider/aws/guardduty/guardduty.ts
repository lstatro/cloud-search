import { Argv } from 'yargs'

export const command = 'guardduty'
export const desc = 'GuardDuty'

const opts = {
  exclude: /.*.test.js/,
}

export const builder = (yargs: Argv) => {
  return yargs.commandDir('cmds', opts).demandCommand(1)
}
