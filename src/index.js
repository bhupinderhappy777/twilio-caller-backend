import { Twilio } from 'twilio';

export default {
    async fetch(request, env) {
        // CORS headers
        const headers = {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type',
        };

        // Handle CORS preflight requests
        if (request.method === 'OPTIONS') {
            return new Response(null, { headers });
        }

        try {
            const {
                TWILIO_ACCOUNT_SID,
                TWILIO_API_KEY,
                TWILIO_API_SECRET,
                TWILIO_TWIML_APP_SID,
            } = env;

            if (!TWILIO_ACCOUNT_SID || !TWILIO_API_KEY || !TWILIO_API_SECRET || !TWILIO_TWIML_APP_SID) {
                throw new Error('Missing Twilio credentials in environment variables.');
            }

            const AccessToken = Twilio.jwt.AccessToken;
            const VoiceGrant = AccessToken.VoiceGrant;

            // Create a random identity for the client
            const identity = `user_${Math.random().toString(36).substr(2, 9)}`;

            const token = new AccessToken(
                TWILIO_ACCOUNT_SID,
                TWILIO_API_KEY,
                TWILIO_API_SECRET,
                { identity: identity }
            );

            const voiceGrant = new VoiceGrant({
                outgoingApplicationSid: TWILIO_TWIML_APP_SID,
                incomingAllow: false, // Set to true to allow incoming calls
            });

            token.addGrant(voiceGrant);

            return new Response(JSON.stringify({ token: token.toJwt() }), {
                headers: { ...headers, 'Content-Type': 'application/json' },
            });

        } catch (error) {
            console.error('Worker Error:', error);
            return new Response(JSON.stringify({ error: error.message }), {
                status: 500,
                headers: { ...headers, 'Content-Type': 'application/json' },
            });
        }
    },
};
