import { Argv } from 'yargs'

export const command = 'elasticache'
export const desc = 'ElastiCache clusters (RDS)'

const opts = {
  exclude: /.*.test.js/,
}

export const builder = (yargs: Argv) => {
  return yargs
    .commandDir('cmd', opts)
    .demandCommand(1)
    .example([
      [
        'elasticache <rule>...',
        'have the cli show you available elasticache scans',
      ],
    ])
}
