import { Argv } from 'yargs'

export const command = 'rds'
export const desc = 'Relational Database Service (RDS)'

export const builder = (yargs: Argv) => {
  return (
    yargs
      // .commandDir('clusters')
      .commandDir('instances')
      .demandCommand(1)
      .example([
        [
          'rds instances <rule>...',
          'have the cli show you available instance rule',
        ],
      ])
  )
}
