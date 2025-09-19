// Updated Cloudflare Worker with Fixed JWT Implementation
function base64url(str) {
  return btoa(str)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

function base64urlArrayBuffer(arrayBuffer) {
  const bytes = new Uint8Array(arrayBuffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return base64url(binary);
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
  
  // 🔧 FIX: Improved key import and signing
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  
  const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(data));
  const encodedSignature = base64urlArrayBuffer(signature);
  
  return data + '.' + encodedSignature;
}

export default {
  async fetch(request, env, ctx) {
    const corsHeaders = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
    };

    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders });
    }

    const url = new URL(request.url);
    const path = url.pathname;

    // Token generation route
    if (path === '/' || path === '/token') {
      return await generateToken(env, corsHeaders);
    }

    // TwiML voice handler route
    if (path === '/voice' && request.method === 'POST') {
      return await handleVoiceCall(request, corsHeaders);
    }

    return new Response('Twilio Worker Active - Routes: / (token), /voice (TwiML)', {
      headers: corsHeaders
    });
  }
};

async function generateToken(env, corsHeaders) {
  try {
    // 🔍 Enhanced validation and logging
    console.log('=== TOKEN GENERATION DEBUG ===');
    console.log('Account SID:', env.TWILIO_ACCOUNT_SID?.substring(0, 10) + '...');
    console.log('API Key:', env.TWILIO_API_KEY?.substring(0, 10) + '...');
    console.log('TwiML App SID:', env.TWILIO_TWIML_APP_SID?.substring(0, 10) + '...');
    console.log('API Secret exists:', !!env.TWILIO_API_SECRET);
    
    // Validate environment variables
    if (!env.TWILIO_ACCOUNT_SID || !env.TWILIO_ACCOUNT_SID.startsWith('AC')) {
      throw new Error('Invalid TWILIO_ACCOUNT_SID - must start with AC');
    }
    if (!env.TWILIO_API_KEY || !env.TWILIO_API_KEY.startsWith('SK')) {
      throw new Error('Invalid TWILIO_API_KEY - must start with SK');
    }
    if (!env.TWILIO_TWIML_APP_SID || !env.TWILIO_TWIML_APP_SID.startsWith('AP')) {
      throw new Error('Invalid TWILIO_TWIML_APP_SID - must start with AP');
    }
    if (!env.TWILIO_API_SECRET) {
      throw new Error('TWILIO_API_SECRET is required');
    }
    
    const now = Math.floor(Date.now() / 1000);
    const identity = 'user';
    
    // 🔧 FIX: Corrected payload structure
    const payload = {
      iss: env.TWILIO_API_KEY,           // API Key SID (issuer)
      sub: env.TWILIO_ACCOUNT_SID,       // Account SID (subject)
      exp: now + 3600,                   // Expires in 1 hour
      iat: now,                          // Issued at
      nbf: now,                          // Not before
      jti: env.TWILIO_API_KEY + '-' + now, // JWT ID
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
    
    console.log('Token payload structure:', {
      iss: payload.iss,
      sub: payload.sub,
      identity: payload.grants.identity,
      app_sid: payload.grants.voice.outgoing.application_sid
    });
    
    const token = await signJWT(payload, env.TWILIO_API_SECRET);
    
    console.log('Token generated successfully');
    console.log('Token length:', token.length);
    
    return new Response(JSON.stringify({ token }), {
      headers: {
        'Content-Type': 'application/json',
        ...corsHeaders
      }
    });
    
  } catch (error) {
    console.error('Token generation error:', error);
    return new Response(JSON.stringify({ 
      error: error.message,
      debug: 'Check environment variables in Cloudflare Worker settings'
    }), {
      status: 500,
      headers: {
        'Content-Type': 'application/json',
        ...corsHeaders
      }
    });
  }
}

async function handleVoiceCall(request, corsHeaders) {
  try {
    const formData = await request.formData();
    const to = formData.get('To');
    const from = formData.get('From');
    
    console.log('Voice call - From:', from, 'To:', to);
    
    // 🔧 IMPORTANT: Replace with your actual Twilio phone number
    const callerId = "+1234567890"; // ⚠️ CHANGE THIS!
    
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