import { Argv } from 'yargs'

export const command = 's3'
export const desc = 'Simple Storage Service (S3)'

const opts = {
  exclude: /.*.test.js/,
}

export const builder = (yargs: Argv) => {
  return yargs
    .commandDir('cmds', opts)
    .demandCommand(1)
    .example([
      [
        's3 IgnorePublicAcls -i myBucketName',
        'scan myBucketName for the IgnorePublicAcls toggle',
      ],
      [
        's3 PublicAccessBlocks -p PROD',
        'check all four public access blocks against all buckets in the PROD account',
      ],
    ])
}
