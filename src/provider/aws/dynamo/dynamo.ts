import { Argv } from 'yargs'

export const command = 'dynamo'
export const desc = 'Amazon DynamoDB'

const opts = {
  exclude: /.*.test.js/,
}

export const builder = (yargs: Argv) => {
  return yargs
    .commandDir('cmds', opts)
    .demandCommand(1)
    .example([
      ['dynamo <rule>...', 'have the cli show you available dynamo rules'],
    ])
}
