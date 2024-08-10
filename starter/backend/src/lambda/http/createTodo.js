import { createLogger } from '../../utils/logger.mjs'
import { getUserId } from '../utils.mjs'
import { createTodo } from '../../businessLogic/todos.mjs'

const httpEventLogger = createLogger('http')

export async function handler(event) {
  // TODO: Implement creating a new TODO item
  httpEventLogger.info(`Now processing createTodo event: ${JSON.stringify(event, null, 2)}`)

  const newTodo = JSON.parse(event.body)

  const userId = getUserId(event)

  const item = await createTodo(newTodo, userId)

  httpEventLogger.info(`Finished processing createTodo event. Todo created: ${JSON.stringify(event, null, 2)}`)

  return {
    statusCode: 201,
    headers: {
      'Access-Control-Allow-Origin': '*'
    },
    body: JSON.stringify({
      item
    })
  }
}