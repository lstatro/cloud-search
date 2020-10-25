import { Argv } from 'yargs'

export const command = 'iam'
export const desc = 'Identity and Access Management (IAM)'

const opts = {
  exclude: /.*.test.js/,
}

export const builder = (yargs: Argv) => {
  return yargs
    .commandDir('users', opts)
    .commandDir('roles', opts)
    .commandDir('groups', opts)
    .demandCommand(1)
    .example([
      [
        'iam user <scan>...',
        'have the cli show you available user scanning options',
      ],
    ])
}
