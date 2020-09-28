#!/usr/bin/env node

// eslint-disable-next-line @typescript-eslint/no-var-requires
require('yargs')
  .commandDir('provider')
  .wrap(null)
  .demandCommand(1)
  .example([
    [
      'cloud-search aws <service>...',
      'have the cli show you available aws scanning options',
    ],
  ])
  .help()
  .strict().argv
