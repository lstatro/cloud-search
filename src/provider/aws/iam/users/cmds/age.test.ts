import 'mocha'
import { mock, restore } from 'aws-sdk-mock'
import { handler, MaxKeyAgeCliInterface } from './age'

describe('iam user key age', () => {
  it('should report okay', async () => {
    mock('IAM', 'listUsers', {
      Users: [
        {
          UserName: 'test',
        },
      ],
    })
    mock('IAM', 'listAccessKeys', {
      AccessKeyMetadata: [
        {
          AccessKeyId: 'test',
          CreateDate: new Date(),
        },
      ],
    })
    await handler({
      resourceId: 'test',
      domain: 'pub',
      maxAge: 30,
    } as MaxKeyAgeCliInterface)

    restore()
  })

  it('should report error', async () => {
    mock('IAM', 'listUsers', {
      Users: [
        {
          UserName: 'test',
        },
      ],
    })
    mock('IAM', 'listAccessKeys', {
      AccessKeyMetadata: [
        {
          AccessKeyId: 'test',
          CreateDate: new Date(0),
        },
      ],
    })
    await handler({
      resourceId: 'test',
      domain: 'pub',
      maxAge: 30,
    } as MaxKeyAgeCliInterface)

    restore()
  })

  it('should handle users without keys', async () => {
    mock('IAM', 'listUsers', {
      Users: [
        {
          UserName: 'test',
        },
      ],
    })
    mock('IAM', 'listAccessKeys', {})
    await handler({
      resourceId: 'test',
      domain: 'pub',
      maxAge: 30,
    } as MaxKeyAgeCliInterface)

    restore()
  })

  it('should handle no users', async () => {
    mock('IAM', 'listUsers', {})
    await handler({
      resourceId: 'test',
      domain: 'pub',
      maxAge: 30,
    } as MaxKeyAgeCliInterface)

    restore()
  })
})
