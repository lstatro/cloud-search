import {
  AuditResultInterface,
  FormatType,
  VerbosityType,
} from '@lstatro/cloud-search'
import ora, { Ora } from 'ora'

import { assert } from 'console'
import chalk from 'chalk'

export default abstract class Provider {
  audits: AuditResultInterface[] = []
  spinner?: Ora

  constructor(
    public rule: string,
    public verbosity: VerbosityType = 'silent',
    public format: FormatType = 'terminal'
  ) {
    /** we want to have a spinner for anything that is not silent */
    if (verbosity !== 'silent') {
      this.spinner = ora({
        prefixText: rule,
      })
    }
  }

  abstract scan<T>(params: T): Promise<void>

  abstract audit<T>(params: T): Promise<void>

  sleep = async (ms: number) => {
    let promise = Promise.resolve()
    promise = new Promise((resolve) => setTimeout(resolve, ms))
    return promise
  }

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

  handleTerminal = () => {
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

  handleJson = () => {
    console.log(JSON.stringify(this.audits, null, 2))
  }

  handleNormalOutput = () => {
    const methods = {
      terminal: this.handleTerminal,
      json: this.handleJson,
    }

    assert(methods[this.format], `unsupported format ${this.format}`)

    methods[this.format]()
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
