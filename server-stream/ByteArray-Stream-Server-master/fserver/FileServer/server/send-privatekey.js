const fs = require('fs');
const path = require('path');
const sodium = require('libsodium-wrappers');

// Path to the Ed25519 private key seed
const ed25519SeedPath = path.join(__dirname, './ed25519-seed.key');

// Function to handle the `/send-privatekey` route
module.exports = async (req, res) => {
    try {
        console.log('[INFO] Request to send private key seed initiated.');

        // Initialize libsodium
        await sodium.ready;

        // Check if the seed file exists
        if (!fs.existsSync(ed25519SeedPath)) {
            throw new Error('Ed25519 seed file not found.');
        }

        // Read the private key seed
        const privateKeySeed = fs.readFileSync(ed25519SeedPath, 'utf8').trim();
        console.log('[DEBUG] Ed25519 Private Key Seed:', privateKeySeed);

        // Decode the private key seed from hex
        const privateKeySeedBytes = Buffer.from(privateKeySeed, 'hex');

        if (privateKeySeedBytes.length !== sodium.crypto_sign_SEEDBYTES) {
            throw new Error('Invalid private key seed length.');
        }

        // Generate Ed25519 key pair from the seed
        const keyPair = sodium.crypto_sign_seed_keypair(privateKeySeedBytes);
        const derivedPublicKeyHex = Buffer.from(keyPair.publicKey).toString('hex');
        console.log('[DEBUG] Derived Public Key (Hex):', derivedPublicKeyHex);

        // Send the private key seed and the derived public key
        res.status(200).json({
            message: 'Ed25519 private key seed sent successfully.',
            privateKeySeed: privateKeySeed, // Hex-encoded seed
            derivedPublicKey: derivedPublicKeyHex, // Derived public key
        });

        console.log('[INFO] Response sent successfully.');
    } catch (err) {
        console.error('[ERROR] Failed to process private key request:', err.message);
        res.status(500).json({ error: 'Internal server error.' });
    }
};
