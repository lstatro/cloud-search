import { AuditResultInterface, VerbosityType } from 'cloud-search'
import chalk from 'chalk'
import ora, { Ora } from 'ora'

export default abstract class Provider {
  audits: AuditResultInterface[] = []
  spinner?: Ora

  constructor(public rule: string, public verbosity: VerbosityType = 'silent') {
    this.rule = rule

    /** we want to have a spinner for anything that is not silent */
    if (verbosity !== 'silent') {
      this.spinner = ora({
        prefixText: rule,
      })
    }
  }

  // getBackOff = (modifier: number) => {
  //   return 100 * (modifier + Math.random()) ** 2
  // }

  // sleep = async (attempt: number) => {
  //   const timer = this.getBackOff(attempt)
  //   await new Promise((resolve) => setTimeout(resolve, this.getBackOff(timer)))
  // }

  handleSpinnerStatus = ({
    method,
    message,
  }: {
    method: 'fail' | 'succeed' | 'start'
    message?: string
  }) => {
    if (this.spinner) {
      this.spinner[method](message)
    }
  }

  handleSpinnerText = ({ message }: { message: string }) => {
    if (this.spinner) {
      this.spinner.text = message
    }
  }

  handleNormalOutput = () => {
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

  handleSilentOutput = () => {
    // do nothing
  }

  output = () => {
    const methods = {
      silent: this.handleSilentOutput,
      normal: this.handleNormalOutput,
    }

    methods[this.verbosity]()
  }
}
