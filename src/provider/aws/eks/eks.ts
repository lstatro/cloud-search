import { Argv } from 'yargs'

export const command = 'eks'
export const desc = 'Elastic Kubernetes Service (EKS)'

const opts = {
  exclude: /.*.test.js/,
}

export const builder = (yargs: Argv) => {
  return yargs.commandDir('cmds', opts).demandCommand(1)
}
