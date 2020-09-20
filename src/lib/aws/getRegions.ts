import assert from 'assert'
import getOptions from './options'
import { EC2 } from 'aws-sdk'

export default async (region: string, profile: string, domain = 'pub') => {
  const regions: string[] = []

  const options = getOptions(profile)

  if (domain === 'pub') {
    if (region === 'all') {
      options.region = 'us-east-1'
      const describeRegions = await new EC2(options).describeRegions().promise()
      assert(describeRegions.Regions, 'unable to describe regions')
      for (const region of describeRegions.Regions) {
        assert(region.RegionName, 'region does not have a name')
        regions.push(region.RegionName)
      }
    } else {
      regions.push(region)
    }
  } else if (domain === 'gov') {
    if (region === 'all') {
      options.region = 'us-gov-west-1'
      const describeRegions = await new EC2(options).describeRegions().promise()
      assert(describeRegions.Regions, 'unable to describe regions')
      for (const region of describeRegions.Regions) {
        assert(region.RegionName, 'region does not have a name')
        regions.push(region.RegionName)
      }
    } else {
      regions.push(region)
    }
  }

  return regions
}
