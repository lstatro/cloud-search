# Cloud-search

A node based CLI that attempts to find and report on common cloud misconfigurations or insecure practices.

This tool is meant to be used by security professionals, system admins, and developers to validate resources are in sane states.

If nothing else, this tool should help spark conversations that lead to better security practices and better dialog with security professionals.

It should go without saying, that passing scans do not mean resources are secure. This tool only takes aim at high level patterns. It's possible that a resource follows established practices, and passes all scans, but still gets breached. This is why it's important to engage in dialog with security professionals early in and often in a project.

Oh, one last note, **this is a scanning and reporting tool, no write actions are taken on the target account.**

# Install

This tool was designed as a global install, however it should still work if installed locally via npx

`npm install -g @lstatro/cloud-search`

# How to find help

Use the `--help` option on any level of the CLI, it should explain what the control is looking for and any additional options it may take.

- The list of services changes often, `cloud-search --help`
- tease though the cli, it should tell you what it wants
- Want to know what a specific compliance state means? Use the `--help` it'll have an explanation of what each state means.

# Disclaimer

Hi Person Behind The Keyboard,

Please understand this tool is in its infancy, as of now this only supports scanning AWS resources, and only a handful of rules at that. More will come in the coming weeks and months.

There are plans to expose some functionality via import/require methods so that users can create their own scanning scripts.

Thanks,

-lst
