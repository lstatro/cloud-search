import { Argv } from 'yargs'

export const command = 'iam'
export const desc = 'Identity and Access Management (IAM)'

export const builder = (yargs: Argv) => {
  return yargs
    .commandDir('users')
    .commandDir('roles')
    .demandCommand(1)
    .example([
      [
        'iam user <scan>...',
        'have the cli show you available user scanning options',
      ],
    ])
}
