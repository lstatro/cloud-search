#!/usr/bin/env node

// eslint-disable-next-line @typescript-eslint/no-var-requires
require('yargs')
  .commandDir('provider')
  .wrap(null)
  .demandCommand(1)
  .help()
  .strict().argv
