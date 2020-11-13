import { Argv } from 'yargs'

export const command = 'dynamodb'
export const desc = 'Amazon DynamoDB'

const opts = {
  exclude: /.*.test.js/,
}

export const builder = (yargs: Argv) => {
  return yargs
    .commandDir('cmds', opts)
    .demandCommand(1)
    .example([
      ['dynamodb <rule>...', 'have the cli show you available dynamodb rules'],
    ])
}
