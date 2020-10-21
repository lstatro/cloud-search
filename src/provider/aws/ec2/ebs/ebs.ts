import { Argv } from 'yargs'

export const command = 'ebs'
export const desc = 'Elastic Block Store (EBS)'

const opts = {
  exclude: /.*.test.js/,
}

export const builder = (yargs: Argv) => {
  return yargs
    .commandDir('cmds', opts)
    .demandCommand(1)
    .example([
      [
        'ebs VolumesEncrypted',
        'check all volumes for default AWS managed key encryption',
      ],
      [
        'ebs VolumesEncrypted -t cmk',
        'check all volumes for customer managed key (CMK) level encryption',
      ],
      [
        'ebs VolumesEncrypted -a <key ARN>',
        'check all volumes for encryption by a specific key',
      ],
      [
        'ebs VolumesEncrypted -a <key ARN> -t cmk',
        'check all volumes for encryption by a specific key, report other volumes as warnings if encrypted',
      ],
    ])
    .epilogue(
      'note: snapshot controls list only snapshots owned by the target account'
    )
}
