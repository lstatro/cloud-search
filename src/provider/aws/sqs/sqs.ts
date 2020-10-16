import { Argv } from 'yargs'

export const command = 'sqs'
export const desc = 'Simple Queuing Service (SQS)'

const opts = {
  exclude: /.*.test.js/,
}

export const builder = (yargs: Argv) => {
  return yargs
    .commandDir('cmds', opts)
    .demandCommand(1)
    .example([
      [
        'sqs <scan>...',
        'have the cli show you available user scanning options',
      ],
    ])
}
