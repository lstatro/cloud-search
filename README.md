# Cloud Search

This CLI tool attempts to find and report on common cloud misconfigration patterns.

Please note this tool is still in its infancy.

Thanks,
-lst

# Install

This tool was designed as a global install, however it should still work if installed locally via npx

`npm install -g @lstatro/cloud-search`

# How to find help

`cloud-search --help`

# Example commands

```bash
lstatro@sooty:~$ cloud-search aws s3 blockPublicAcls --profile fluffy
blockPublicAcls ✔
state      region          rule                      physicalId
FAIL       n/a             blockPublicAcls           ar-ue1-artifacts
```
