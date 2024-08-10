import Axios from 'axios'
import jsonwebtoken from 'jsonwebtoken'
import { createLogger } from '../../utils/logger.mjs'

const logger = createLogger('auth')

const jwksUrl = 'https://test-endpoint.auth0.com/.well-known/jwks.json'

const certificate = `-----BEGIN CERTIFICATE-----
MIIDHTCCAgWgAwIBAgIJL42r+jPLONF6MA0GCSqGSIb3DQEBCwUAMCwxKjAoBgNV
BAMTIWRldi04M3RwbWY0aGlqczhvZmZ1LnVzLmF1dGgwLmNvbTAeFw0yNDA3MjUx
NTUwMThaFw0zODA0MDMxNTUwMThaMCwxKjAoBgNVBAMTIWRldi04M3RwbWY0aGlq
czhvZmZ1LnVzLmF1dGgwLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC
ggEBAN4mFxaod04x+Ncgn8nt7VwWQagXC6Mj+BeYPMcWiNzRQAW7MK1KZ1QZpdqM
nN2sf+8Pwg34ogf6tZHy60WHZu2EGwOYp4ZgxgNv2IvHdxAi7tHlkGtAzEQBAZgV
VpbO5nJY+ViAeqCAIrMn5fL1nGrX1iBwl/H9u9B2pAzRC6cO4HXmL9hgKs0twKCs
zPvfpfA/2fm25wzz6QOqBr+7sXribP0P+npUhr0QcF5p1KSJWop421s0oVxcKtUN
afcrGa7JoqPPMWjphaoOlF4m5hoDEAuxKxH/zhAaIBozLEmIl6h12+BeOEaBHGos
q+JvlW3xTlfe2dckxksJfr3wEYsCAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAd
BgNVHQ4EFgQUsjZFb8FCNf6dCwCcRbJFwKxvsIIwDgYDVR0PAQH/BAQDAgKEMA0G
CSqGSIb3DQEBCwUAA4IBAQA2kGTMKDngqZ7jd0kz9NHQTIMCPsVu0MNxfiUirhHd
sq+RASPZZASb6s9sLbDJTGiBd4ke31ljj8/KVyPQxEub7dR20U0Z4BYROdVzhDW6
HgEXSykvOGHYpg9qElSaa0vNkkitkAzkLdXx+8uIWH56nVQAiwCmlVH0OSm6YPae
79ak8htUQmnPCcSglJIq5Fvj5HgaYHcn3zVuB8Rwkx9AiWzy+MkQ5UZYzyH0X2ve
rdWUOapxxRIVYKXy0DtuWoXIYPhLhyrx+Jo7trfHlSQPcXHmOGfhJnZW8Kh0+RKq
oCRvWHuGMJq38ygMf2tkKpA/Ilu7HC3aSamx1NcUeGWI
-----END CERTIFICATE-----`

export async function handler(event) {
  try {
    const jwtToken = await verifyToken(event.authorizationToken)

    return {
      principalId: jwtToken.sub,
      policyDocument: {
        Version: '2012-10-17',
        Statement: [
          {
            Action: 'execute-api:Invoke',
            Effect: 'Allow',
            Resource: '*'
          }
        ]
      }
    }
  } catch (e) {
    logger.error('User not authorized', { error: e.message })

    return {
      principalId: 'user',
      policyDocument: {
        Version: '2012-10-17',
        Statement: [
          {
            Action: 'execute-api:Invoke',
            Effect: 'Deny',
            Resource: '*'
          }
        ]
      }
    }
  }
}

async function verifyToken(authHeader) {
  if (!authHeader) throw new Error('No authorization header')

  if (!authHeader.toLowerCase().startsWith('bearer ')) {
    throw new Error('Invalid authorization header')
  }

  const token = getToken(authHeader)
  const jwt = jsonwebtoken.decode(token, { complete: true })

  // TODO: Implement token verification
  return jsonwebtoken.verify(token, certificate, { algorithms: ['RS256'] });
}

function getToken(authHeader) {
  if (!authHeader) throw new Error('No authentication header')

  if (!authHeader.toLowerCase().startsWith('bearer '))
    throw new Error('Invalid authentication header')

  const split = authHeader.split(' ')
  const token = split[1]

  return token
}
