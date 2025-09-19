// Complete Cloudflare Worker - Handles both Token Generation AND TwiML
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
    const corsHeaders = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
    };

    // Handle CORS preflight requests
    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders });
    }

    const url = new URL(request.url);
    const path = url.pathname;

    // 🎯 ROUTE 1: Token generation (your existing code)
    if (path === '/' || path === '/token') {
      return await generateToken(env, corsHeaders);
    }

    // 🎯 ROUTE 2: TwiML voice handler (NEW - REQUIRED!)
    if (path === '/voice' && request.method === 'POST') {
      return await handleVoiceCall(request, corsHeaders);
    }

    // Default response
    return new Response('Twilio Worker Active - Routes: / (token), /voice (TwiML)', {
      headers: corsHeaders
    });
  }
};

// Your token generation function (with fixes)
async function generateToken(env, corsHeaders) {
  try {
    const now = Math.floor(Date.now() / 1000);
    const identity = 'user';
    
    const payload = {
      iss: env.TWILIO_API_KEY,        // 🔧 Make sure this is your API Key SID (starts with SK)
      sub: env.TWILIO_ACCOUNT_SID,    // 🔧 Your Account SID (starts with AC)
      exp: now + 3600,
      iat: now,
      nbf: now,
      jti: env.TWILIO_API_KEY + '-' + now,
      grants: {
        identity: identity,
        voice: {
          outgoing: {
            application_sid: env.TWILIO_TWIML_APP_SID  // 🔧 Your TwiML App SID (starts with AP)
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
        ...corsHeaders
      }
    });
  } catch (error) {
    console.error('Token generation error:', error);
    return new Response(JSON.stringify({ error: error.message }), {
      status: 500,
      headers: {
        'Content-Type': 'application/json',
        ...corsHeaders
      }
    });
  }
}

// NEW: TwiML voice call handler (REQUIRED for calls to work!)
async function handleVoiceCall(request, corsHeaders) {
  try {
    const formData = await request.formData();
    const to = formData.get('To');
    const from = formData.get('From');
    
    console.log('Voice call - From:', from, 'To:', to);
    
    // 🔧 IMPORTANT: Replace with your verified phone number or Twilio number
    const callerId = "+1234567890"; // ⚠️ CHANGE THIS TO YOUR REAL NUMBER!
    
    const twiml = `<?xml version="1.0" encoding="UTF-8"?>
<Response>
    <Dial callerId="${callerId}">${to}</Dial>
</Response>`;

    return new Response(twiml, {
      headers: {
        ...corsHeaders,
        'Content-Type': 'text/xml'
      }
    });
    
  } catch (error) {
    console.error('TwiML generation error:', error);
    
    const errorTwiml = `<?xml version="1.0" encoding="UTF-8"?>
<Response>
    <Say>Sorry, there was an error processing your call.</Say>
</Response>`;

    return new Response(errorTwiml, {
      headers: {
        ...corsHeaders,
        'Content-Type': 'text/xml'
      }
    });
  }
}