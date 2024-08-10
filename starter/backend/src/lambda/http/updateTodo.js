import { createLogger } from '../../utils/logger.mjs'
import { updateTodo } from "../../businessLogic/todos.mjs";
import { getUserId } from "../utils.mjs";

const httpEventLogger = createLogger('http')

export async function handler(event) {
  const updateRequest = JSON.parse(event.body);
  const todoId = event.pathParameters.todoId
  const userId = getUserId(event)

  httpEventLogger.info(`Now processing updateTodo ${JSON.stringify(updateRequest, null, 2)}, id: ${todoId}`)
  await updateTodo(userId, todoId, updateRequest);
  httpEventLogger.info(`Finished processing updateTodo ${JSON.stringify(updateRequest, null, 2)}, id: ${todoId}`)

  return {
    statusCode: 204,
    headers: {
      'Access-Control-Allow-Origin': '*'
    },
  };
}
