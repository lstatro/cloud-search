<p align="center">
  <a href="https://coveralls.io/github/lstatro/cloud-search?branch=develop">
    <img src="https://coveralls.io/repos/github/lstatro/cloud-search/badge.svg?branch=develop"/>
  </a>
</p>

---

# Cloud-search

A node based CLI that attempts to find and report on common cloud misconfigurations or insecure practices.

This tool is meant to be used by security professionals, system admins, or developers to validate resources are in sane states.

If nothing else, this tool should help spark conversations that lead to better security practices and better dialog with security professionals.

It should go without saying, that passing scans do not mean resources are secure. This tool only takes aim at high level patterns. Further, it's possible that a resource follows secure practices, and passes all known scans, but still be insecure. This is why it's important to engage security professionals early and often in a project.

Oh, one last note, **this is a scanning and reporting tool, no write actions are taken on target accounts.**

# Install CLI and use globally

`npm install -g @lstatro/cloud-search`

# Install module and use locally as a package

Import a cloud provider's name off of `@lstatro/cloud-search`. See examples below.

- Most cli scans are also exported as modules, follow the cli's nesting structure to tease out specifics
  > **note** some scans are instances of a generic scan class. For example, `BlockPublicAcls` is a specific instance of the `PublicAccessBlocks`

* AWS - `@lstatro/cloud-search/AWS`

  ```typescript
  import { sns } from '@lstatro/cloud-search/AWS'

  const main = async () => {
    const scan = new sns.TopicEncrypted({
      region: 'us-east-1',
      keyType: 'aws',
    })

    await scan.start()

    console.log(scan.audits)
  }

  main()
  ```

- ~~GCP - `@lstatro/cloud-search/GCP`~~ (pending)
- ~~Azure - `@lstatro/cloud-search/Azure`~~ (pending)

# How to find help

Use `--help` at any CLI level, it will contain information about the control and any additional options it may take.

- The list of services changes often, `cloud-search --help`
- tease though the cli, it should tell you what it wants

```shell
lst@atro:[~]: cloud-search aws --help
cli.js aws

aws cloud provider

Commands:
  cli.js aws ec2          Elastic Cloud Compute (EC2)
  cli.js aws s3           Simple Storage Service (S3)
  cli.js aws iam          Identity and Access Management (IAM)
  cli.js aws sns          Simple Notification Service (SNS)
  cli.js aws sqs          Simple Queuing Service (SQS)
  cli.js aws rds          Relational Database Service (RDS)
  cli.js aws kms          Key Management Service (KMS)
  cli.js aws cloudtrail   CloudTrail
  cli.js aws elasticache  ElastiCache clusters
  cli.js aws guardduty    GuardDuty
  cli.js aws neptune      Amazon Neptune
  cli.js aws dynamodb     Amazon DynamoDB
```

# outputs and formatting

- When running as a CLI everything is output to terminal including the `json` format type.
- The `json` output type includes more information then the standard terminal output

# FAQ

## How can I save a point in time report?

- Pipe terminal to a file for later post processing. If necessary change the format to JSON
- Install cloud-search as a package use the necessary scan to generate a report

## My newly developed commands are not showing up in the CLI what gives?

- Did you do a `npm run build`? You can also run `tsc -w` to watch for changes,
  > **note** when creating or deleting files it's possible for the build folder gets polluted. If that happens, it's best to do `npm run build` as it will delete `./build` and start a fresh build.

# How to run the project locally

- `git clone` - this repo and check out the desired branch
  - `master` stable and is is the `latest` npm build
  - **`develop` may contain breaking changes _(lots of dragons here!)_**
- `npm install` - to install dependencies
- `npm run build` - to transpile ts files into a new the `./build` folder
- `npm link ./build` - to run commands locally

> **note**, if upgrading from a release prior 1.9.0 you'll need to `un` and `re` link the project as the build structure is different

> **note** if developing locally it may be best to uninstall `@lstatro/cloud-search` from global to avoid the possiblity for any confusion `npm uninstall @lstatro/cloud-search -g`
