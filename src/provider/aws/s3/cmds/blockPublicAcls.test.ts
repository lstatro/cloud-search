import 'mocha'
import { handler } from './blockPublicAcls'

describe('blockPublicAcls', () => {
  it('should attempt to invoke a test', async () => {
    await handler({
      _: ['test'],
      $0: 'test',
      profile: 'test',
      resourceId: 'test',
      domain: 'pub',
      region: 'us-east-1',
    })
  })
})
