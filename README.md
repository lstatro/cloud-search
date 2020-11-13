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

# Install the CLI and use globally

`npm install -g @lstatro/cloud-search`

# Install locally and use as a package for scripting'

Import the cloud provider's name off of the `@lstatro/cloud-search` package. See the examples below.

- Most of the supported scans are also exported as modules, and follow the cli's nesting structure.
  > **note** some cli commands are abstractions on a larger class and are not exported. For example, `BlockPublicAcls` is an abstraction on `PublicAccessBlocks`. If you want to discover that do not have the block public acl toggle turned on you'll need to call `PublicAccessBlocks` with its desired parameters.

* AWS - `@lstatro/cloud-search/AWS`

  ```typescript
  import { sns } from '@lstatro/cloud-search/AWS'

  const main = async () => {
    const scan = new sns.TopicEncrypted({
      region: 'us-east-1',
      profile: 'fluffy',
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

# outputs and formatting

- When running as a CLI everything is output to terminal including the `json` format type.
- The `json` output type includes more information then the standard terminal output

# FAQ

## How can I save a point in time report?

Pipe terminal to a file for later post processing. If necessary change the format to JSON to make post processing easier.

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
