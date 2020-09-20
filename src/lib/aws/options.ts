import { SharedIniFileCredentials } from 'aws-sdk'
import { AWSClientOptionsInterface } from 'cloud-scan'

/** generates and returns aws-sdk client service options */
export default (profile?: string) => {
  let options: AWSClientOptionsInterface
  if (profile) {
    const credentials = new SharedIniFileCredentials({ profile })
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
