// Complete Working Cloudflare Worker for Twilio
function base64url(source) {
  // Convert to base64url format
  let encodedSource = btoa(source);
  
  // Remove padding and replace characters
  encodedSource = encodedSource.replace(/=+$/, '');
  encodedSource = encodedSource.replace(/\+/g, '-');
  encodedSource = encodedSource.replace(/\//g, '_');
  
  return encodedSource;
}

function arrayBufferToBase64url(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return base64url(binary);
}

async function createJWT(payload, secret) {
  const header = {
    alg: 'HS256',
    typ: 'JWT'
  };
  
  // Encode header and payload
  const encodedHeader = base64url(JSON.stringify(header));
  const encodedPayload = base64url(JSON.stringify(payload));
  
  // Create signature
  const data = `${encodedHeader}.${encodedPayload}`;
  const encoder = new TextEncoder();
  
  // Import key
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  
  // Sign the data
  const signature = await crypto.subtle.sign('HMAC', cryptoKey, encoder.encode(data));
  const encodedSignature = arrayBufferToBase64url(signature);
  
  return `${data}.${encodedSignature}`;
}

export default {
  async fetch(request, env, ctx) {
    const corsHeaders = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
    };

    // Handle CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders });
    }

    const url = new URL(request.url);
    
    // Debug endpoint to check environment variables
    if (url.pathname === '/debug') {
      const debug = {
        timestamp: new Date().toISOString(),
        env_vars: {
          TWILIO_ACCOUNT_SID: env.TWILIO_ACCOUNT_SID ? env.TWILIO_ACCOUNT_SID.substring(0, 5) + '...' : 'MISSING',
          TWILIO_API_KEY: env.TWILIO_API_KEY ? env.TWILIO_API_KEY.substring(0, 5) + '...' : 'MISSING',
          TWILIO_API_SECRET: env.TWILIO_API_SECRET ? 'Present' : 'MISSING',
          TWILIO_TWIML_APP_SID: env.TWILIO_TWIML_APP_SID ? env.TWILIO_TWIML_APP_SID.substring(0, 5) + '...' : 'MISSING'
        }
      };
      
      return new Response(JSON.stringify(debug, null, 2), {
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    }

    // Voice webhook for TwiML
    if (url.pathname === '/voice' && request.method === 'POST') {
      try {
        const formData = await request.formData();
        const to = formData.get('To');
        
        console.log('Voice call to:', to);
        
        const twiml = `<?xml version="1.0" encoding="UTF-8"?>
<Response>
    <Dial callerId="+1234567890">${to}</Dial>
</Response>`;

        return new Response(twiml, {
          headers: { 'Content-Type': 'text/xml', ...corsHeaders }
        });
      } catch (error) {
        const errorTwiml = `<?xml version="1.0" encoding="UTF-8"?>
<Response>
    <Say>Call failed</Say>
</Response>`;
        
        return new Response(errorTwiml, {
          headers: { 'Content-Type': 'text/xml', ...corsHeaders }
        });
      }
    }

    // Token generation (default route)
    try {
      console.log('=== TOKEN GENERATION START ===');
      
      // Validate environment variables
      const requiredVars = {
        TWILIO_ACCOUNT_SID: env.TWILIO_ACCOUNT_SID,
        TWILIO_API_KEY: env.TWILIO_API_KEY,
        TWILIO_API_SECRET: env.TWILIO_API_SECRET,
        TWILIO_TWIML_APP_SID: env.TWILIO_TWIML_APP_SID
      };
      
      const missing = Object.entries(requiredVars)
        .filter(([key, value]) => !value)
        .map(([key]) => key);
      
      if (missing.length > 0) {
        console.error('Missing environment variables:', missing);
        throw new Error(`Missing environment variables: ${missing.join(', ')}`);
      }
      
      // Validate format
      if (!env.TWILIO_ACCOUNT_SID.startsWith('AC')) {
        throw new Error('TWILIO_ACCOUNT_SID must start with AC');
      }
      if (!env.TWILIO_API_KEY.startsWith('SK')) {
        throw new Error('TWILIO_API_KEY must start with SK');
      }
      if (!env.TWILIO_TWIML_APP_SID.startsWith('AP')) {
        throw new Error('TWILIO_TWIML_APP_SID must start with AP');
      }
      
      console.log('Environment variables validated');
      
      // Create JWT payload
      const now = Math.floor(Date.now() / 1000);
      const identity = 'user';
      
      const payload = {
        iss: env.TWILIO_API_KEY,
        sub: env.TWILIO_ACCOUNT_SID,
        exp: now + 3600, // 1 hour
        iat: now,
        nbf: now,
        jti: `${env.TWILIO_API_KEY}-${now}`,
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
      
      console.log('Payload created:', {
        iss: payload.iss,
        sub: payload.sub,
        identity: payload.grants.identity,
        app_sid: payload.grants.voice.outgoing.application_sid
      });
      
      // Generate JWT
      const token = await createJWT(payload, env.TWILIO_API_SECRET);
      
      console.log('Token generated successfully, length:', token.length);
      console.log('=== TOKEN GENERATION END ===');
      
      return new Response(JSON.stringify({ token }), {
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
      
    } catch (error) {
      console.error('Token generation failed:', error);
      
      return new Response(JSON.stringify({
        error: error.message,
        timestamp: new Date().toISOString(),
        hint: 'Check environment variables and Twilio credentials'
      }), {
        status: 500,
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    }
  }
};