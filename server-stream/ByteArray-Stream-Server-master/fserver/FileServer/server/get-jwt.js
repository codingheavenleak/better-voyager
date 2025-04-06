const fs = require('fs');
const path = require('path');
const jwt = require('jsonwebtoken');
const crypto = require('crypto'); // [new] uuid

// paths
const privateKeyFilePath = path.join(__dirname, './private.pem'); 

module.exports = (req, res) => {
    try {
        const privateKey = fs.readFileSync(privateKeyFilePath);

        const payload = {
            iss: 'scylla-server', // issuer
            sub: 'public-key-delivery', // subject (purpose)
            aud: 'scylla-client', // delviery or smth idk
            iat: Math.floor(Date.now() / 1000), // time of issue
            exp: Math.floor(Date.now() / 1000) + 600, // expiration time (10 minutes from now)
            jti: crypto.randomUUID(), // uuid (randomly generated) -> todo: store in db
        };

        const jwtToken = jwt.sign(payload, privateKey, {
            algorithm: 'RS256',
        });

        console.log('[INFO] Generated JWT for public key retrieval.');
        console.log(`[DEBUG] JWT Payload: ${JSON.stringify(payload, null, 2)}`);
        console.log(`[DEBUG] JWT Token: ${jwtToken}`);

        res.status(200).json({
            message: 'Public key JWT generated successfully.',
            jwt: jwtToken,
        });

        // logs info in client storage for now, todo: log it in db also
        console.log('[INFO] Please use the following JWT in the Authorization header for subsequent requests:');
        console.log(`[INFO] Authorization: Bearer ${jwtToken}`);
    } catch (err) {
        console.error('[ERROR] Failed to generate public key JWT:', err.message);
        res.status(500).json({ error: 'Internal server error.' });
    }
};
