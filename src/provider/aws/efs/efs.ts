import { Argv } from 'yargs'

export const command = 'efs'
export const desc = 'Elastic File Syste,'

const opts = {
  exclude: /.*.test.js/,
}

export const builder = (yargs: Argv) => {
  return yargs
    .commandDir('cmds', opts)
    .demandCommand(1)
    .example([['efs <rule>...', 'have the cli show you available efs scans']])
}
