// Example Cloudflare Worker for Twilio Token Generation
// This file should be deployed as a Cloudflare Worker

import Twilio from 'twilio';

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
      // Initialize Twilio client
      const client = Twilio(env.TWILIO_ACCOUNT_SID, env.TWILIO_AUTH_TOKEN);
      
      // Generate access token
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