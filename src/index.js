// Helper function to sign a JWT token using the Web Crypto API
async function signJWT(header, payload, secret) {
    const encoder = new TextEncoder();
    const encodedHeader = base64URLEncode(JSON.stringify(header));
    const encodedPayload = base64URLEncode(JSON.stringify(payload));
    const data = `${encodedHeader}.${encodedPayload}`;
    const key = await crypto.subtle.importKey('raw', encoder.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(data));
    const encodedSignature = base64URLEncode(new Uint8Array(signature));
    return `${data}.${encodedSignature}`;
}

// Helper function for Base64URL encoding
function base64URLEncode(data) {
    if (typeof data === 'string') {
        data = new TextEncoder().encode(data);
    }
    const base64 = btoa(String.fromCharCode.apply(null, data));
    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

export default {
    async fetch(request, env) {
        const url = new URL(request.url);
        const path = url.pathname;

        const corsHeaders = {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type',
        };

        if (request.method === 'OPTIONS') {
            return new Response(null, { headers: corsHeaders });
        }

        // --- ROUTER LOGIC ---
        // Route for getting a token
        if (path === '/' || path === '/token') {
            return generateToken(env, corsHeaders);
        }

        // Route for handling Twilio's voice webhook
        if (path === '/voice' && request.method === 'POST') {
            return await handleVoice(request, env, corsHeaders);
        }
        // --- END ROUTER ---

        return new Response('Not Found', { status: 404, headers: corsHeaders });
    },
};

// This function generates the Access Token
async function generateToken(env, headers) {
    try {
        const { TWILIO_ACCOUNT_SID, TWILIO_API_KEY, TWILIO_API_SECRET, TWILIO_TWIML_APP_SID } = env;
        if (!TWILIO_ACCOUNT_SID || !TWILIO_API_KEY || !TWILIO_API_SECRET || !TWILIO_TWIML_APP_SID) {
            throw new Error('Missing Twilio credentials in environment variables.');
        }
        const identity = `user_${Math.random().toString(36).substr(2, 9)}`;
        const header = { "alg": "HS256", "typ": "JWT", "cty": "twilio-fpa;v=1" };
        const now = Math.floor(Date.now() / 1000);
        const payload = {
            "jti": `${TWILIO_API_KEY}-${now}`,
            "iss": TWILIO_API_KEY,
            "sub": TWILIO_ACCOUNT_SID,
            "exp": now + 3600,
            "grants": {
                "identity": identity,
                "voice": { "outgoing": { "application_sid": TWILIO_TWIML_APP_SID } }
            }
        };
        const token = await signJWT(header, payload, TWILIO_API_SECRET);
        return new Response(JSON.stringify({ token: token }), { headers: { ...headers, 'Content-Type': 'application/json' } });
    } catch (error) {
        console.error('Worker Error:', error);
        return new Response(JSON.stringify({ error: error.message }), { status: 500, headers: { ...headers, 'Content-Type': 'application/json' } });
    }
}

// This function handles the voice webhook and returns TwiML
async function handleVoice(request, env, headers) {
    const formData = await request.formData();
    const to = formData.get('To');
    const { TWILIO_PHONE_NUMBER } = env; // Your Twilio phone number for Caller ID

    if (!TWILIO_PHONE_NUMBER) {
        console.error('TWILIO_PHONE_NUMBER environment variable not set in Cloudflare Worker.');
        // Return a TwiML response with an error message
        const errorTwiml = `<?xml version="1.0" encoding="UTF-8"?><Response><Say>We're sorry, the application is not configured correctly. The caller ID is missing.</Say></Response>`;
        return new Response(errorTwiml, { headers: { ...headers, 'Content-Type': 'text/xml' } });
    }

    const twiml = `<?xml version="1.0" encoding="UTF-8"?>
<Response>
    <Dial callerId="${TWILIO_PHONE_NUMBER}">
        <Number>${to}</Number>
    </Dial>
</Response>`;

    return new Response(twiml, { headers: { ...headers, 'Content-Type': 'text/xml' } });
}
