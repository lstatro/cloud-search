# Cloud-search

A node based CLI that attempts to find and report on common cloud misconfigurations or insecure practices.

This tool is meant to be used by security professionals, system admins, and developers to validate resources are in sane states.

If nothing else, this tool should help spark conversations that lead to better security practices and better dialog with security professionals.

It should go without saying, that passing scans do not mean resources are secure. This tool only takes aim at high level patterns. It's possible that a resource follows established practices, and passes all scans, but still gets breached. This is why it's important to engage in dialog with security professionals early in and often in a project.

Oh, one last note, **this is a scanning and reporting tool, no write actions are taken on target accounts.**

# Install

`npm install -g @lstatro/cloud-search`

# How to find help

Use `--help` at any CLI level, it will contain information about the control and any additional options it may take.

- The list of services changes often, `cloud-search --help`
- tease though the cli, it should tell you what it wants
- Want to know what a specific compliance state means? Use the `--help` it'll have an explanation of what each state means.

---

<p align="center">
  <a href="https://coveralls.io/github/lstatro/cloud-search?branch=develop">
    <img src="https://coveralls.io/repos/github/lstatro/cloud-search/badge.svg?branch=develop"/>
  </a>
</p>
