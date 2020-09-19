import { SharedIniFileCredentials } from 'aws-sdk'

/** generates and returns aws-sdk client service options */
export default (profile?: string) => {
  let options
  if (profile) {
    const credentials = new SharedIniFileCredentials({ profile })
    options = {
      accessKeyId: credentials.accessKeyId,
      secretAccessKey: credentials.secretAccessKey,
      sessionToken: credentials.sessionToken,
    }
  } else {
    options = {}
  }
  return options
}
