import { Argv } from 'yargs'

export const command = 'users'
export const desc = 'IAM user rules'

export const builder = (yargs: Argv) => {
  return yargs
    .commandDir('cmds')
    .demandCommand(1)
    .example([
      [
        'aws iam users MaxKeyAge -m 7',
        'fail any key that is older then 7 days',
      ],
    ])
}
