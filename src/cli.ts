#!/usr/bin/env node

// eslint-disable-next-line @typescript-eslint/no-var-requires
require('yargs')
  .commandDir('aws', { recurse: true })
  .demandCommand(1, 'provide at least one command path')
  .help().argv
