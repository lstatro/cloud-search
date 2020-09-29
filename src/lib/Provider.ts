import { AuditResultInterface } from 'cloud-search'
import chalk from 'chalk'
import ora, { Ora } from 'ora'

export default abstract class Provider {
  audits: AuditResultInterface[] = []
  spinner: Ora
  rule: string

  constructor(rule: string) {
    this.rule = rule
    this.spinner = ora({
      prefixText: rule,
    })
  }

  getBackOff = (modifier: number) => {
    return (modifier + Math.random()) ** 2 * 1000
  }

  sleep = async (attempt: number) => {
    const timer = this.getBackOff(attempt)
    await new Promise((resolve) => setTimeout(resolve, this.getBackOff(timer)))
  }

  output = () => {
    const log = console.log

    log(
      chalk.bold('state'.padEnd(10)),
      chalk.bold('region'.padEnd(15)),
      chalk.bold('rule'.padEnd(25)),
      chalk.bold('physicalId')
    )

    for (const audit of this.audits) {
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
}
