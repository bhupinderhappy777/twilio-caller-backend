// Example Cloudflare Worker for Twilio Token Generation
// This file should be deployed as a Cloudflare Worker

// JWT utilities for Twilio Access Token generation
function base64url(str) {
  return btoa(str)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

async function signJWT(payload, secret) {
  const header = {
    alg: 'HS256',
    typ: 'JWT'
  };
  
  const encodedHeader = base64url(JSON.stringify(header));
  const encodedPayload = base64url(JSON.stringify(payload));
  
  const data = encodedHeader + '.' + encodedPayload;
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  
  const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(data));
  const encodedSignature = base64url(String.fromCharCode(...new Uint8Array(signature)));
  
  return data + '.' + encodedSignature;
}

export default {
  async fetch(request, env, ctx) {
    // Handle CORS preflight requests
    if (request.method === 'OPTIONS') {
      return new Response(null, {
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type',
        },
      });
    }

    try {
      // Generate Twilio Access Token
      const now = Math.floor(Date.now() / 1000);
      const identity = 'user'; // You can make this dynamic based on request
      
      const payload = {
        iss: env.TWILIO_API_KEY,
        sub: env.TWILIO_ACCOUNT_SID,
        exp: now + 3600, // Token expires in 1 hour
        iat: now,
        nbf: now,
        jti: env.TWILIO_API_KEY + '-' + now,
        grants: {
          identity: identity,
          voice: {
            outgoing: {
              application_sid: env.TWILIO_TWIML_APP_SID
            },
            incoming: {
              allow: true
            }
          }
        }
      };
      
      const token = await signJWT(payload, env.TWILIO_API_SECRET);
      
      return new Response(JSON.stringify({ token: token }), {
        headers: {
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*',
        },
      });
    } catch (error) {
      return new Response(JSON.stringify({ error: error.message }), {
        status: 500,
        headers: {
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*',
        },
      });
    }
  },
};