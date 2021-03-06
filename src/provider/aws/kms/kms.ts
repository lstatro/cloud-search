import { Argv } from 'yargs'

export const command = 'kms'
export const desc = 'Key Management Service (KMS)'

const opts = {
  exclude: /.*.test.js/,
}

export const builder = (yargs: Argv) => {
  return yargs
    .commandDir('cmds', opts)
    .demandCommand(1)
    .example([
      [
        `${command} <scan>...`,
        'have the cli show you available scanning options',
      ],
    ])
}
