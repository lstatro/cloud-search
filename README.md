# Disclaimer

Please note this tool is still in its infancy, as of now this only supports scanning AWS resources, and only a handful of rules at that.

Thanks,

-lst

# Cloud-search

A node based CLI that attempts to find and report on common cloud misconfigration patterns.

This tool is meant to be used by security professionals, system admins, and developers to validate that resources are in sane states. We do not aim to be the one and only, or even the single best, source of secure practices in the cloud, but we hope it's a good start.

If nothing else, it should help spark up conversations that lead to better security practices within your organization. If it does then we've done what we set out to do!

# Install

This tool was designed as a global install, however it should still work if installed locally via npx

`npm install -g @lstatro/cloud-search`

# How to find help

- `cloud-search --help`
- lol, look at the code, we're not perfect!

# A note on credentials

## AWS

**The preferred method of use use credential profiles and pass that profile name into the request.**

However, this should also work with the other nodejs standard methods of storing and using AWS credentials. The heart of the beast relies on the AWS javascript SDK and ultimately how [AWS handles credentials precedence](https://docs.aws.amazon.com/sdk-for-javascript/v2/developer-guide/setting-credentials-node.html).

# Example commands

```bash
lstatro@sooty:~$ cloud-search aws s3 blockPublicAcls --profile fluffy
blockPublicAcls ✔
state      region          rule                      physicalId
FAIL       n/a             blockPublicAcls           ar-ue1-artifacts
```

# A Note Regions

Unless told otherwise, the tool will run scans across all regions. It is possible to override this behavior by passing a specific region into a request.

If requesting a scan of a specific resource, you will also have to pass in the region that resource lives in.

For global service, the region may be safely omitted. When the system goes to generate the API end-point it'll default to something sane like `us-east-1`.

# Compliance (Audit) States

## <span style="color:green">**OK**</span>

**OK** states mean that the resource has an expected configuration for the specific rule in question

## <span style="color:orange">**UNKNOWN**</span>

**UNKNOWN** states occur when the system is aware of a resource but for some reason is unable to determine its specific compliance state.

User access or resource policy permissions allowing for listing of a resource, but not an explicit describe of a resource commonly result in a UNKNOWN state.

### Not all <span style="color:orange">**UNKNOWN**</span> states are bad

Denying list and/or describe calls just means the system cannot observe the resource. The resource may be just fine, it just requires a closer look.

### How to fix <span style="color:orange">**UNKNOWN**</span> states

These are typically the result of permission issues with the resource or the user making the describe API calls. Verify your profiles access permissions.

## <span style="color:red">**FAIL**</span>

**FAIL** means the resource does not have the expected configuration for the specific rule in question. Resources in a **FAIL** state should have further inspection.

Note, not all resources in a **FAIL** state are threats. Consider a public S3 bucket- if the bucket is hosting a website it should be public. The rules that scan for public access will indicate it's failed, but that's okay.
