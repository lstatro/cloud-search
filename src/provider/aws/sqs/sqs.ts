import { Argv } from 'yargs'

export const command = 'sqs'
export const desc = 'Simple Queuing Service (SQS)'

export const builder = (yargs: Argv) => {
  return yargs
    .commandDir('cmds')
    .demandCommand(1)
    .example([
      [
        'sqs <scan>...',
        'have the cli show you available user scanning options',
      ],
    ])
}
