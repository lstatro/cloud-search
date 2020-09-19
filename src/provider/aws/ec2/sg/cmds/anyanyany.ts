import { Arguments, CommandBuilder } from 'yargs'

export const command = 'anyanyany [args]'
export const desc =
  'search for security groups that allow any ip to access any range on any port'

export const builder: CommandBuilder = {}

export const handler = async (args: Arguments) => {
  console.log(args)
}
