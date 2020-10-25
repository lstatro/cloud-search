#!/usr/bin/env node

// eslint-disable-next-line @typescript-eslint/no-var-requires
require('yargs')
  .commandDir('provider')
  .wrap(null)
  .demandCommand(1)
  .option('verbosity', {
    alias: 'v',
    describe: 'how much data to dump to console',
    type: 'string',
    default: 'normal',
    choices: ['normal', 'silent'],
  })
  .option('format', {
    alias: 'f',
    describe: 'output format',
    type: 'string',
    default: 'terminal',
    choices: ['terminal', 'json'],
  })
  .example([
    [
      'cloud-search aws <service>...',
      'have the cli show you available aws scanning options',
    ],
  ])
  .help()
  .strict().argv
