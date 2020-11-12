import { Argv } from 'yargs'

export const command = 'xlb'
export const desc =
  'classic, application, and network load-balancer scans (xlb)'

const opts = {
  exclude: /.*.test.js/,
}

export const builder = (yargs: Argv) => {
  return yargs.commandDir('cmds', opts).demandCommand(1)
}
