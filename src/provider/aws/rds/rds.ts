import { Argv } from 'yargs'

export const command = 'rds'
export const desc = 'Relational Database Service (RDS)'

const opts = {
  exclude: /.*.test.js/,
}

export const builder = (yargs: Argv) => {
  return yargs
    .commandDir('clusters', opts)
    .commandDir('instances', opts)
    .demandCommand(1)
}
