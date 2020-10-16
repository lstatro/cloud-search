import { Argv } from 'yargs'

export const command = 'sns'
export const desc = 'Simple Notification Service (SNS)'

const opts = {
  exclude: /.*.test.js/,
}

export const builder = (yargs: Argv) => {
  return yargs
    .commandDir('cmds', opts)
    .demandCommand(1)
    .example([
      [
        'sns <scan>...',
        'have the cli show you available user scanning options',
      ],
    ])
}
