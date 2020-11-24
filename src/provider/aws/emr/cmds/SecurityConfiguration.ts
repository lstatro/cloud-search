import {
  AuditResultInterface,
  AWSScannerInterface,
} from '@lstatro/cloud-search'
import assert from 'assert'
import { AWS } from '../../../../lib/aws/AWS'

const rule = 'SecurityConfiguration'

export const command = `${rule} [args]`

export const desc = `EMR clusters should be launched with a security
configuration group

  OK      - Cluster launched with group
  UNKNOWN - Unable to determine if cluster was launched with a group
  FAIL    - Cluster not launched with group

  resourceId - cluster ID

  note: Scans only look at active clusters.  It's still possible to manually
        audit terminated instances by passing in the terminated resource id in
        resource scan (... emr -r us-east-1 -i j-XXXXX )

        valid scan states are:
          - STARTING
          - BOOTSTRAPPING
          - RUNNING
          - WAITING
          - TERMINATING

`

export class SecurityConfiguration extends AWS {
  audits: AuditResultInterface[] = []
  service = 'emr'
  global = false

  constructor(public params: AWSScannerInterface) {
    super({ ...params, rule })
  }

  async audit({ resource, region }: { resource: string; region: string }) {
    const options = this.getOptions()
    options.region = region

    assert(resource, 'emr cluster id is required')

    const audit = this.getDefaultAuditObj({ resource: resource, region })

    const describeCluster = await new this.AWS.EMR(options)
      .describeCluster({
        ClusterId: resource,
      })
      .promise()

    if (describeCluster.Cluster) {
      if (describeCluster.Cluster.SecurityConfiguration) {
        audit.state = 'OK'
      } else {
        audit.state = 'FAIL'
      }
    }

    this.audits.push(audit)
  }

  scan = async ({
    resourceId,
    region,
  }: {
    resourceId: string
    region: string
  }) => {
    const options = this.getOptions()
    options.region = region

    if (resourceId) {
      await this.audit({ resource: resourceId, region })
    } else {
      const listClusters = await new this.AWS.EMR(options)
        .listClusters({
          ClusterStates: [
            'STARTING',
            'BOOTSTRAPPING',
            'RUNNING',
            'WAITING',
            'TERMINATING',
          ],
        })
        .promise()

      if (listClusters.Clusters) {
        for (const cluster of listClusters.Clusters) {
          assert(cluster.Id, 'cluster ID not found')
          await this.audit({ resource: cluster.Id, region })
        }
      }
    }
  }
}

export const handler = async (args: AWSScannerInterface) => {
  const scanner = new SecurityConfiguration(args)

  await scanner.start()
  scanner.output()
  return scanner.audits
}
