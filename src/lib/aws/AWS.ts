import { AWSClientOptionsInterface } from 'cloud-scan'
import { SharedIniFileCredentials, EC2 } from 'aws-sdk'
import Provider from '../Provider'

import assert from 'assert'

interface AWSParamsInterface {
  profile: string
  rule: string
  resourceId?: string
  domain: string
  region: string
}

interface ScanInterface {
  region: string
  resourceId?: string
}

export default abstract class AWS extends Provider {
  abstract service: string

  options: AWSClientOptionsInterface

  rule: string
  domain: string
  region: string
  regions: string[] = []

  profile?: string
  resourceId?: string

  constructor(params: AWSParamsInterface) {
    super(params.rule)

    this.rule = params.rule
    this.domain = params.domain
    this.region = params.region

    this.options = this.getOptions()
  }

  abstract async scan(params: ScanInterface): Promise<void>

  abstract audit<T>(resource: T, region: string): Promise<void>

  getOptions = () => {
    let options: AWSClientOptionsInterface
    if (this.profile) {
      const credentials = new SharedIniFileCredentials({
        profile: this.profile,
      })
      options = {
        credentials: {
          accessKeyId: credentials.accessKeyId,
          secretAccessKey: credentials.secretAccessKey,
          sessionToken: credentials.sessionToken,
        },
        region: '',
      }
    } else {
      options = {}
    }
    return options
  }

  getRegions = async () => {
    /** is this pub or gov clouds? */
    if (this.domain === 'pub') {
      /** are we set to do all regions? */
      if (this.region === 'all') {
        /** welp, lets start with by setting us-east-1 and getting a list of all regions */
        this.options.region = 'us-east-1'
        const describeRegions = await new EC2(this.options)
          .describeRegions()
          .promise()

        /** we should have a list of regions, if so for each region get the name and push it to the regions list */
        assert(describeRegions.Regions, 'unable to describe regions')
        for (const region of describeRegions.Regions) {
          assert(region.RegionName, 'region does not have a name')
          this.regions.push(region.RegionName)
        }
      } else {
        /**
         * looks like this is a single resource request, that resource must
         * live in a specific region and the user should have provided
         * that region.  If t hey didn't then the calling service should fail
         */
        this.regions.push(this.region)
      }

      /** go read the comments for pub cloud and repeat for gov cloud :P */
    } else if (this.domain === 'gov') {
      if (this.region === 'all') {
        this.options.region = 'us-gov-west-1'
        const describeRegions = await new EC2(this.options)
          .describeRegions()
          .promise()
        assert(describeRegions.Regions, 'unable to describe regions')
        for (const region of describeRegions.Regions) {
          assert(region.RegionName, 'region does not have a name')
          this.regions.push(region.RegionName)
        }
      } else {
        this.regions.push(this.region)
      }
    }
  }

  handleRegions = async () => {
    await this.getRegions()

    for (const region of this.regions) {
      this.spinner.text = region
      await this.scan({ region })
    }
  }

  start = async () => {
    try {
      this.spinner.start()
      if (this.resourceId) {
        await this.scan(this.region, this.resourceId)
      } else {
        await this.handleRegions()
      }
      this.spinner.succeed()
    } catch (err) {
      this.spinner.fail(err.message)
    }
  }
}
