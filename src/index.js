import Twilio from 'twilio';

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
      const formData = await request.formData();
      const to = formData.get('To');
      
      // Create TwiML response for outbound call
      const twiml = `<?xml version="1.0" encoding="UTF-8"?>
<Response>
    <Dial callerId="${env.TWILIO_PHONE_NUMBER}">${to}</Dial>
</Response>`;

      return new Response(twiml, {
        headers: {
          'Content-Type': 'text/xml',
          'Access-Control-Allow-Origin': '*',
        },
      });
    }

    // Handle debug endpoint (existing code)
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

    // Handle token generation (existing code)
    try {
      const AccessToken = Twilio.jwt.AccessToken;
      const VoiceGrant = AccessToken.VoiceGrant;
      
      const token = new AccessToken(
        env.TWILIO_ACCOUNT_SID,
        env.TWILIO_API_KEY,
        env.TWILIO_API_SECRET,
        { identity: 'user' }
      );
      
      const voiceGrant = new VoiceGrant({
        outgoingApplicationSid: env.TWILIO_TWIML_APP_SID,
        incomingAllow: true,
      });
      
      token.addGrant(voiceGrant);
      
      return new Response(JSON.stringify({ token: token.toJwt() }), {
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