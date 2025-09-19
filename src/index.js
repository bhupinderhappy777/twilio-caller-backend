export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    
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

    // Handle TwiML for outbound calls
    if (url.pathname === '/voice' && request.method === 'POST') {
      try {
        const formData = await request.formData();
        const to = formData.get('To');
        
        // Create TwiML response for outbound call
        const twiml = `<?xml version="1.0" encoding="UTF-8"?>
<Response>
    <Dial callerId="${env.TWILIO_PHONE_NUMBER || '+1234567890'}">${to}</Dial>
</Response>`;

        return new Response(twiml, {
          headers: {
            'Content-Type': 'text/xml',
            'Access-Control-Allow-Origin': '*',
          },
        });
      } catch (error) {
        return new Response(`<Response><Say>Error processing call</Say></Response>`, {
          headers: {
            'Content-Type': 'text/xml',
            'Access-Control-Allow-Origin': '*',
          },
        });
      }
    }

    // Handle debug endpoint
    if (url.pathname === '/debug') {
      return new Response(JSON.stringify({
        timestamp: new Date().toISOString(),
        env_vars: {
          TWILIO_ACCOUNT_SID: env.TWILIO_ACCOUNT_SID?.substring(0, 5) + '...',
          TWILIO_API_KEY: env.TWILIO_API_KEY?.substring(0, 5) + '...',
          TWILIO_API_SECRET: env.TWILIO_API_SECRET ? 'Present' : 'Missing',
          TWILIO_TWIML_APP_SID: env.TWILIO_TWIML_APP_SID?.substring(0, 5) + '...',
          TWILIO_PHONE_NUMBER: env.TWILIO_PHONE_NUMBER?.substring(0, 5) + '...',
        }
      }, null, 2), {
        headers: {
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*',
        },
      });
    }

    // Handle token generation (main endpoint)
    try {
      // Create JWT manually (since Twilio SDK might not work in Workers)
      const header = {
        "alg": "HS256",
        "typ": "JWT"
      };

      const now = Math.floor(Date.now() / 1000);
      const payload = {
        "iss": env.TWILIO_API_KEY,
        "sub": env.TWILIO_ACCOUNT_SID,
        "exp": now + 3600, // 1 hour
        "iat": now,
        "nbf": now,
        "jti": `${env.TWILIO_API_KEY}-${now}`,
        "grants": {
          "identity": "user",
          "voice": {
            "outgoing": {
              "application_sid": env.TWILIO_TWIML_APP_SID
            },
            "incoming": {
              "allow": true
            }
          }
        }
      };

      // Simple JWT creation
      const encodedHeader = btoa(JSON.stringify(header)).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
      const encodedPayload = btoa(JSON.stringify(payload)).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
      
      const signatureInput = `${encodedHeader}.${encodedPayload}`;
      
      // Create HMAC-SHA256 signature
      const key = new TextEncoder().encode(env.TWILIO_API_SECRET);
      const data = new TextEncoder().encode(signatureInput);
      
      const cryptoKey = await crypto.subtle.importKey(
        'raw',
        key,
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['sign']
      );
      
      const signature = await crypto.subtle.sign('HMAC', cryptoKey, data);
      const encodedSignature = btoa(String.fromCharCode(...new Uint8Array(signature)))
        .replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
      
      const token = `${encodedHeader}.${encodedPayload}.${encodedSignature}`;
      
      return new Response(JSON.stringify({ token }), {
        headers: {
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*',
        },
      });
      
    } catch (error) {
      return new Response(JSON.stringify({ 
        error: error.message,
        stack: error.stack 
      }), {
        status: 500,
        headers: {
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*',
        },
      });
    }
  },
};