import chalk from 'chalk'
import { AuditResultInterface } from 'cloud-scan'

export default (audits: AuditResultInterface[]) => {
  const log = console.log

  log(
    chalk.bold('state'.padEnd(10)),
    chalk.bold('region'.padEnd(15)),
    chalk.bold('rule'.padEnd(25)),
    chalk.bold('physicalId')
  )

  for (const audit of audits) {
    if (audit.state === 'OK') {
      log(
        chalk.green.bold(audit.state.padEnd(10)),
        chalk.bold(audit.region.padEnd(15)),
        chalk.bold(audit.rule.padEnd(25)),
        chalk.bold(audit.physicalId)
      )
    } else if (audit.state === 'FAIL') {
      log(
        chalk.red.bold(audit.state.padEnd(10)),
        chalk.bold(audit.region.padEnd(15)),
        chalk.bold(audit.rule.padEnd(25)),
        chalk.bold(audit.physicalId)
      )
    } else {
      log(
        chalk.yellow.bold(audit.state.padEnd(10)),
        chalk.bold(audit.region.padEnd(15)),
        chalk.bold(audit.rule.padEnd(25)),
        chalk.bold(audit.physicalId)
      )
    }
  }
}