import { Argv } from 'yargs'

export const command = 'emr'
export const desc = 'Elastic Map Reduce (EMR)'

const opts = {
  exclude: /.*.test.js/,
}

export const builder = (yargs: Argv) => {
  return yargs.commandDir('cmds', opts).demandCommand(1)
}
