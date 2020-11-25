import { Argv } from 'yargs'

export const command = 'emr'
export const desc = 'Elastic Map Reduce (EMR)'

const opts = {
  exclude: /.*.test.js/,
}

const epilog = `
**************************** Instance States ***********************************

Scans only look at active clusters.  It's still possible to manually
audit terminated instances by passing in the terminated resource id in
resource scan (... emr -r us-east-1 -i j-XXXXX )

valid states are:
  - STARTING
  - BOOTSTRAPPING
  - RUNNING
  - WAITING
  - TERMINATING
`

export const builder = (yargs: Argv) => {
  return yargs.commandDir('cmds', opts).demandCommand(1).epilog(epilog)
}
