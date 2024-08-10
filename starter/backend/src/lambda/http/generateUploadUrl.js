import {createLogger} from '../../utils/logger.mjs'
import {setAttachmentUrl} from '../../businessLogic/todos.mjs'
import {getUserId} from "../utils.mjs";
import {getFormattedUrl, getUploadUrl} from "../../fileStorage/attachmentUtils.mjs";

const httpEventLogger = createLogger('http')

export async function handler(event) {
  const todoId = event.pathParameters.todoId;
  httpEventLogger.info(`Now processing generateUploadUrl event: ${todoId}`)

  const image = JSON.parse(event.body)
  const userId = getUserId(event);

  const attachmentUrl = getFormattedUrl(todoId)
  const uploadUrl = await getUploadUrl(todoId)

  await setAttachmentUrl(userId, todoId, image, attachmentUrl)

  httpEventLogger.info(`Finished processing generateUploadUrl event: ${todoId}`)

  return {
    statusCode: 201,
    headers: {
      'Access-Control-Allow-Origin': '*'
    },
    body: JSON.stringify({
      uploadUrl
    })
  }
}

