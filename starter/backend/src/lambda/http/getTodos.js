import { getUserId } from '../utils.mjs'
import { createLogger } from '../../utils/logger.mjs'
import { findByUserId } from '../../businessLogic/todos.mjs'

const httpLogger = createLogger('http')

export async function handler(event) {
  httpLogger.info(`Now processing getTodos event ${JSON.stringify(event, null, 2)}`)

  const userId = getUserId(event)

  const items = (await findByUserId(userId))

  httpLogger.info(`Finished processing getTodos event ${JSON.stringify(event, null, 2)}`)

  return {
    statusCode: 200,
    headers: {
      'Access-Control-Allow-Origin': '*'
    },
    body: JSON.stringify({
      items
    })
  }
}