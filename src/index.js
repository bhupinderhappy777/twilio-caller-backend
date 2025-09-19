// Helper function to sign a JWT token using the Web Crypto API
async function signJWT(header, payload, secret) {
    const encoder = new TextEncoder();
    
    // Base64URL encode the header and payload
    const encodedHeader = base64URLEncode(JSON.stringify(header));
    const encodedPayload = base64URLEncode(JSON.stringify(payload));
    
    const data = `${encodedHeader}.${encodedPayload}`;
    
    // Import the secret key
    const key = await crypto.subtle.importKey(
        'raw',
        encoder.encode(secret),
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['sign']
    );
    
    // Sign the data
    const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(data));
    const encodedSignature = base64URLEncode(new Uint8Array(signature));
    
    return `${data}.${encodedSignature}`;
}

// Helper function for Base64URL encoding
function base64URLEncode(data) {
    // If data is a string, convert it to a Uint8Array first
    if (typeof data === 'string') {
        data = new TextEncoder().encode(data);
    }
    // Now data is guaranteed to be a Uint8Array
    const base64 = btoa(String.fromCharCode.apply(null, data));
    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}


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

            // Create a random identity for the client
            const identity = `user_${Math.random().toString(36).substr(2, 9)}`;

            // Manually construct the JWT header and payload
            const header = {
                "alg": "HS256",
                "typ": "JWT",
                "cty": "twilio-fpa;v=1"
            };

            const now = Math.floor(Date.now() / 1000);
            const payload = {
                "jti": `${TWILIO_API_KEY}-${now}`,
                "iss": TWILIO_API_KEY,
                "sub": TWILIO_ACCOUNT_SID,
                "exp": now + 3600, // Token expires in 1 hour
                "grants": {
                    "identity": identity,
                    "voice": {
                        "outgoing": {
                            "application_sid": TWILIO_TWIML_APP_SID
                        }
                    }
                }
            };

            const token = await signJWT(header, payload, TWILIO_API_SECRET);

            return new Response(JSON.stringify({ token: token }), {
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
