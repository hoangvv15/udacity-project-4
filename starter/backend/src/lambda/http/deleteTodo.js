import { createLogger } from '../../utils/logger.mjs'
import { deleteTodo } from '../../businessLogic/todos.mjs'
import { getUserId } from "../utils.mjs";

const httpEventLogger = createLogger('http')

export async function handler(event) {
  const todoId = event.pathParameters.todoId
  httpEventLogger.info(`Now processing deleteTodo event: ${todoId}`)
  const userId = getUserId(event)

  await deleteTodo(userId, todoId)

  return {
    statusCode: 204,
    headers: {
      'Access-Control-Allow-Origin': '*'
    },
  }
}