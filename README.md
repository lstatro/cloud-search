# Cloud-search

A node based CLI that attempts to find and report on common cloud misconfigurations or insecure practices.

This tool is meant to be used by security professionals, system admins, and developers to validate resources are in sane states.

If nothing else, this tool should help spark conversations that lead to better security practices and better dialog with security professionals.

It should go without saying, that passing scans do not mean resources are secure. This tool only takes aim at high level patterns. It's possible that a resource follows established practices, and passes all scans, but still gets breached. This is why it's important to engage in dialog with security professionals early in and often in a project.

Oh, one last note, **this is a scanning and reporting tool, no write actions are taken on the target account.**

# Disclaimer

Hi Person Behind The Keyboard,

Please understand this tool is in its infancy, as of now this only supports scanning AWS resources, and only a handful of rules at that. More will come in the coming weeks and months.

There are plans to expose some functionality via import/require methods so that users can create their own scanning scripts.

Thanks,

-lst

# Install

This tool was designed as a global install, however it should still work if installed locally via npx

`npm install -g @lstatro/cloud-search`

# How to find help

Use the `--help` option on any level of the CLI, it should explain what the control is looking for and any additional options it may take.

- The list of services changes often, `cloud-search --help`
- tease though the cli, it should tell you what it wants
- lol, look at the code, we're not perfect!

# Credentials

Credential management will vary by cloud provider.

## AWS

**The tool supports AWS credential profiles.** However, this also works with the other nodejs standard methods of storing and using AWS credentials. The beasts heart beats to the rhythm of the javascript aws-sdk- and ultimately how [AWS handles credentials precedence](https://docs.aws.amazon.com/sdk-for-javascript/v2/developer-guide/setting-credentials-node.html).

# Command Examples

- With profile doing a scan of a global service

```bash
lstatro@sooty:~$ cloud-search aws s3 blockPublicAcls --profile fluffy
blockPublicAcls ✔
state      region          rule                      physicalId
FAIL       n/a             blockPublicAcls           ar-ue1-xxxxxxxx
```

- Without a profile scanning a single resource

```bash
lstatro@sooty:~$ cloud-search aws ec2 vpc igwAttachedToVpc -r ap-northeast-2 -i igw-xxxxxxxx
igwAttachedToVpc √
state      region          rule                      physicalId
FAIL       ap-northeast-2  igwAttachedToVpc          igw-xxxxxxxx
```

- With a profile doing a scan of of all regions
- **Note**, regions show up more then once because there is more then one resource in that region
- **Note**, that af-south-1 is opted in and therefore shows in the scan

```bash

lstatro@sooty:~$ cloud-search aws ec2 sg publicPermission -p fluffy
publicPermission √ us-west-2
state      region          rule                      physicalId
OK         af-south-1      publicPermission          sg-xxxxxxxx
OK         eu-north-1      publicPermission          sg-xxxxxxxx
OK         ap-south-1      publicPermission          sg-xxxxxxxx
OK         eu-west-3       publicPermission          sg-xxxxxxxx
OK         eu-west-2       publicPermission          sg-xxxxxxxx
OK         eu-west-1       publicPermission          sg-xxxxxxxx
OK         ap-northeast-2  publicPermission          sg-xxxxxxxx
OK         ap-northeast-1  publicPermission          sg-xxxxxxxx
OK         sa-east-1       publicPermission          sg-xxxxxxxx
OK         ca-central-1    publicPermission          sg-xxxxxxxx
OK         ap-southeast-1  publicPermission          sg-xxxxxxxx
OK         ap-southeast-2  publicPermission          sg-xxxxxxxx
OK         eu-central-1    publicPermission          sg-xxxxxxxx
OK         us-east-1       publicPermission          sg-xxxxxxxx
OK         us-east-1       publicPermission          sg-xxxxxxxx
OK         us-east-1       publicPermission          sg-xxxxxxxx
FAIL       us-east-1       publicPermission          sg-xxxxxxxx
OK         us-east-1       publicPermission          sg-xxxxxxxx
OK         us-east-2       publicPermission          sg-xxxxxxxx
OK         us-east-2       publicPermission          sg-xxxxxxxx
FAIL       us-east-2       publicPermission          sg-xxxxxxxx
FAIL       us-east-2       publicPermission          sg-xxxxxxxx
OK         us-east-2       publicPermission          sg-xxxxxxxx
OK         us-west-1       publicPermission          sg-xxxxxxxx
FAIL       us-west-1       publicPermission          sg-xxxxxxxx
OK         us-west-2       publicPermission          sg-xxxxxxxx
```

# Regions and Scans

Unless told otherwise, the tool will run scans across all regions returned by `ec2.describeRegions()`. It is possible to override this behavior by passing a specific region into a request.

If requesting a scan of a specific resource, you will also have to pass in the region that resource lives in.

For global service, the region may be safely omitted. When the system goes to generate the API end-point it'll default to something sane like `us-east-1`.

> **Note**, opt in regions are omitted by the describe call therefore they're omitted by the tool until they're opted in.

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
