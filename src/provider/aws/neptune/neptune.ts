import { Argv } from 'yargs'

export const command = 'neptune'
export const desc = 'Amazon Neptune'

const opts = {
  exclude: /.*.test.js/,
}

export const builder = (yargs: Argv) => {
  return (
    yargs
      .commandDir('clusters', opts)
      // .commandDir('instances', opts)
      .demandCommand(1)
      .example([
        [
          'neptune clusters <rule>...',
          'have the cli show you available cluster rule',
        ],
      ])
  )
}
