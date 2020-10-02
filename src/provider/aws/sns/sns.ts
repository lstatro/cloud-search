import { Argv } from 'yargs'

export const command = 'sns'
export const desc = 'Simple Notification Service (SNS)'

export const builder = (yargs: Argv) => {
  return yargs
    .commandDir('cmds')
    .demandCommand(1)
    .example([
      [
        'sns TopicEncrypted <scan>...',
        'have the cli show you available user scanning options',
      ],
    ])
}
