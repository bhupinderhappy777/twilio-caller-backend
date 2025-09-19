// Cloudflare Worker for Twilio Voice Dialer
// Handles JWT token generation and TwiML responses

export default {
    async fetch(request, env, ctx) {
        const url = new URL(request.url);
        const path = url.pathname;

        // Add CORS headers
        const corsHeaders = {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type, Authorization',
        };

        // Handle preflight requests
        if (request.method === 'OPTIONS') {
            return new Response(null, { headers: corsHeaders });
        }

        try {
            // Token generation endpoint
            if (path === '/token' && request.method === 'GET') {
                return await generateAccessToken(env, corsHeaders);
            }
            
            // Voice webhook endpoint
            if (path === '/voice' && request.method === 'POST') {
                return await handleVoiceWebhook(request, env, corsHeaders);
            }
            
            // Debug endpoint
            if (path === '/debug' && request.method === 'GET') {
                return await handleDebug(env, corsHeaders);
            }
            
            // TwiML App status check endpoint
            if (path === '/check-twiml' && request.method === 'GET') {
                return await checkTwiMLAppStatus(env, corsHeaders);
            }

            return new Response('Not Found', { status: 404, headers: corsHeaders });

        } catch (error) {
            console.error('Worker error:', error);
            return new Response(
                JSON.stringify({ 
                    error: 'Internal server error', 
                    message: error.message 
                }), 
                { 
                    status: 500, 
                    headers: { ...corsHeaders, 'Content-Type': 'application/json' } 
                }
            );
        }
    }
};

async function generateAccessToken(env, corsHeaders) {
    const { TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_TWIML_APP_SID } = env;

    if (!TWILIO_ACCOUNT_SID || !TWILIO_AUTH_TOKEN || !TWILIO_TWIML_APP_SID) {
        return new Response(
            JSON.stringify({ 
                error: 'Missing environment variables',
                required: ['TWILIO_ACCOUNT_SID', 'TWILIO_AUTH_TOKEN', 'TWILIO_TWIML_APP_SID']
            }), 
            { 
                status: 500, 
                headers: { ...corsHeaders, 'Content-Type': 'application/json' } 
            }
        );
    }

    try {
        // Create JWT using Auth Token (not API Key)
        const header = {
            "alg": "HS256",
            "typ": "JWT"
        };

        const now = Math.floor(Date.now() / 1000);
        const payload = {
            "iss": TWILIO_ACCOUNT_SID,  // Use Account SID as issuer for Auth Token
            "exp": now + 3600,
            "grants": {
                "voice": {
                    "incoming": {
                        "allow": true
                    },
                    "outgoing": {
                        "application_sid": TWILIO_TWIML_APP_SID
                    }
                }
            }
        };

        const token = await signJWT(header, payload, TWILIO_AUTH_TOKEN);

        console.log('Generated token with:', {
            issuer: TWILIO_ACCOUNT_SID,
            appSid: TWILIO_TWIML_APP_SID,
            tokenLength: token.length
        });

        return new Response(
            JSON.stringify({ 
                token: token,
                debug: {
                    issuer: TWILIO_ACCOUNT_SID,
                    appSid: TWILIO_TWIML_APP_SID,
                    tokenLength: token.length,
                    expiresIn: 3600
                }
            }), 
            { 
                headers: { ...corsHeaders, 'Content-Type': 'application/json' } 
            }
        );

    } catch (error) {
        console.error('Token generation failed:', error);
        return new Response(
            JSON.stringify({ 
                error: 'Token generation failed', 
                message: error.message 
            }), 
            { 
                status: 500, 
                headers: { ...corsHeaders, 'Content-Type': 'application/json' } 
            }
        );
    }
}

async function handleVoiceWebhook(request, env, corsHeaders) {
    const { TWILIO_PHONE_NUMBER } = env;
    
    // Parse form data from Twilio
    const formData = await request.formData();
    const from = formData.get('From');
    const to = formData.get('To');
    
    console.log('Voice call received:', { from, to });

    // Generate TwiML response
    const twiml = `<?xml version="1.0" encoding="UTF-8"?>
<Response>
    <Dial callerId="${TWILIO_PHONE_NUMBER || from}">
        <Number>${to}</Number>
    </Dial>
</Response>`;

    return new Response(twiml, {
        headers: { ...corsHeaders, 'Content-Type': 'text/xml' }
    });
}

async function handleDebug(env, corsHeaders) {
    const { TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_TWIML_APP_SID, TWILIO_PHONE_NUMBER } = env;
    
    const debug = {
        timestamp: new Date().toISOString(),
        environment: {
            accountSid: TWILIO_ACCOUNT_SID ? `${TWILIO_ACCOUNT_SID.substring(0, 10)}...` : 'NOT SET',
            authToken: TWILIO_AUTH_TOKEN ? `${TWILIO_AUTH_TOKEN.substring(0, 10)}...` : 'NOT SET',
            twimlAppSid: TWILIO_TWIML_APP_SID ? `${TWILIO_TWIML_APP_SID.substring(0, 10)}...` : 'NOT SET',
            phoneNumber: TWILIO_PHONE_NUMBER || 'NOT SET'
        },
        status: 'Worker is running'
    };

    return new Response(JSON.stringify(debug, null, 2), {
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
}

async function checkTwiMLAppStatus(env, corsHeaders) {
    const { TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_TWIML_APP_SID } = env;

    if (!TWILIO_ACCOUNT_SID || !TWILIO_AUTH_TOKEN || !TWILIO_TWIML_APP_SID) {
        return new Response(
            JSON.stringify({ 
                success: false,
                error: 'Missing environment variables',
                required: ['TWILIO_ACCOUNT_SID', 'TWILIO_AUTH_TOKEN', 'TWILIO_TWIML_APP_SID']
            }), 
            { 
                status: 400, 
                headers: { ...corsHeaders, 'Content-Type': 'application/json' } 
            }
        );
    }

    try {
        // Create Basic Auth header
        const credentials = btoa(`${TWILIO_ACCOUNT_SID}:${TWILIO_AUTH_TOKEN}`);
        
        // Call Twilio REST API to get TwiML App details
        const response = await fetch(
            `https://api.twilio.com/2010-04-01/Accounts/${TWILIO_ACCOUNT_SID}/Applications/${TWILIO_TWIML_APP_SID}.json`,
            {
                method: 'GET',
                headers: {
                    'Authorization': `Basic ${credentials}`,
                    'Content-Type': 'application/x-www-form-urlencoded'
                }
            }
        );

        if (!response.ok) {
            const errorText = await response.text();
            console.error('Twilio API error:', response.status, errorText);
            
            return new Response(
                JSON.stringify({ 
                    success: false,
                    error: `Twilio API error: ${response.status}`,
                    details: errorText
                }), 
                { 
                    status: response.status, 
                    headers: { ...corsHeaders, 'Content-Type': 'application/json' } 
                }
            );
        }

        const twimlApp = await response.json();
        
        console.log('TwiML App details retrieved:', {
            sid: twimlApp.sid,
            name: twimlApp.friendly_name,
            voiceUrl: twimlApp.voice_url,
            voiceMethod: twimlApp.voice_method
        });

        return new Response(
            JSON.stringify({ 
                success: true,
                twimlApp: {
                    sid: twimlApp.sid,
                    friendlyName: twimlApp.friendly_name,
                    voiceUrl: twimlApp.voice_url,
                    voiceMethod: twimlApp.voice_method,
                    statusCallbackUrl: twimlApp.status_callback_url,
                    statusCallbackMethod: twimlApp.status_callback_method,
                    dateCreated: twimlApp.date_created,
                    dateUpdated: twimlApp.date_updated
                }
            }), 
            { 
                headers: { ...corsHeaders, 'Content-Type': 'application/json' } 
            }
        );

    } catch (error) {
        console.error('Error checking TwiML App:', error);
        return new Response(
            JSON.stringify({ 
                success: false,
                error: 'Failed to check TwiML App status', 
                message: error.message 
            }), 
            { 
                status: 500, 
                headers: { ...corsHeaders, 'Content-Type': 'application/json' } 
            }
        );
    }
}

// JWT signing function using Web Crypto API
async function signJWT(header, payload, secret) {
    const encoder = new TextEncoder();
    
    // Encode header and payload
    const encodedHeader = base64URLEncode(JSON.stringify(header));
    const encodedPayload = base64URLEncode(JSON.stringify(payload));
    
    // Create signature
    const data = `${encodedHeader}.${encodedPayload}`;
    const key = await crypto.subtle.importKey(
        'raw',
        encoder.encode(secret),
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['sign']
    );
    
    const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(data));
    const encodedSignature = base64URLEncode(new Uint8Array(signature));
    
    return `${data}.${encodedSignature}`;
}

function base64URLEncode(data) {
    if (typeof data === 'string') {
        data = new TextEncoder().encode(data);
    }
    
    const base64 = btoa(String.fromCharCode(...data));
    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}
