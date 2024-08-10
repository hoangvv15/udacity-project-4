import Axios from 'axios'
import {API_DESTINATION} from "../config"


export async function getTodos(idToken) {
  console.log('Fetching todos')

  const response = await Axios.get(
    `${API_DESTINATION}/todos`,
    {
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${idToken}`
      }
    }
  )
  console.log('Todos:', response.data)
  return response.data.items
}

export async function createTodo(idToken, newTodo) {
  const response = await Axios.post(
    `${API_DESTINATION}/todos`,
    JSON.stringify(newTodo),
    {
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${idToken}`
      }
    }
  )
  return response.data.item
}

export async function patchTodo(idToken, todoId, updatedTodo) {
  console.log("In patch todo")
  await Axios.patch(
    `${API_DESTINATION}/todos/${todoId}`,
    JSON.stringify(updatedTodo),
    {
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${idToken}`
      }
    }
  )
}

export async function deleteTodo(idToken, todoId) {
  console.log("In patch todo")
  await Axios.delete(`${API_DESTINATION}/todos/${todoId}`, {
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${idToken}`
    }
  })
}

export async function getUploadUrl(idToken, todoId) {
  const response = await Axios.post(
    `${API_DESTINATION}/todos/${todoId}/attachment`,
    '',
    {
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${idToken}`
      }
    }
  )
  return response.data.uploadUrl
}

export async function uploadFile(uploadUrl, file) {
  await Axios.put(uploadUrl, file)
}
