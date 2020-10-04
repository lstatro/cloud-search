import 'mocha'
import { useFakeTimers, SinonFakeTimers } from 'sinon'
import { mock, restore } from 'aws-sdk-mock'

describe('sns topic encryption', () => {
  const now = new Date(0)
  let clock: SinonFakeTimers

  beforeEach(() => {
    clock = useFakeTimers(now)
    mock('EC2', 'describeRegions', { Regions: [{ RegionName: 'us-east-1' }] })
  })

  afterEach(() => {
    clock.restore()
    restore()
  })
})
