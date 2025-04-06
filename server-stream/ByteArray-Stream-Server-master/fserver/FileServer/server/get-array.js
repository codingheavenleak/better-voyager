const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const url = require('url');

const secretKey = 'X9f2kP7qLm3nR8tUvWxYzA5bCdEgHjKl'; // Replace with a secure, randomly generated key

function deriveKey(salt) {
    return crypto.pbkdf2Sync(secretKey, salt, 100000, 32, 'sha256');
}

function encrypt(data) {
    const iv = crypto.randomBytes(16);
    const salt = crypto.randomBytes(16);
    const key = deriveKey(salt);
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    let encrypted = cipher.update(data, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    console.log('IV:', iv.toString('hex'));
    console.log('Salt:', salt.toString('hex'));
    console.log('Encrypted data length:', encrypted.length);
    return iv.toString('hex') + salt.toString('hex') + encrypted;
}

function sendEncryptedFile(filePath, res) {
    if (!fs.existsSync(filePath)) {
        console.error('[ERROR] File not found.');
        return res.status(404).send('File not found.');
    }

    try {
        let fileContent = fs.readFileSync(filePath, 'utf8');
        const encryptedData = encrypt(fileContent);

        const response = {
            data: encryptedData
        };

        res.status(200).json(response);
        console.log('[INFO] Encrypted response sent successfully.');
    } catch (err) {
        console.error('[ERROR] Failed to process request:', err.message);
        res.status(500).send('Internal server error.');
    }
}

module.exports = (req, res) => {
    const clientIP = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
    console.log(`[INFO] Received request from IP: ${clientIP}`);

    const queryObject = url.parse(req.url, true).query;
    const windowsVersion = queryObject.version;

    console.log(`[INFO] Client Windows version: ${windowsVersion}`);

    if (windowsVersion === '22H2') {
        const filePath = path.join(__dirname, './Stream/22h2.h');
        sendEncryptedFile(filePath, res);
    } else if (windowsVersion === '24H2') {
        const filePath = path.join(__dirname, './Stream/24h2.h');
        sendEncryptedFile(filePath, res);
    } else {
        res.status(200).json({ data: 'false' });
        console.log('[INFO] Unsupported Windows version. Sent "false" response.');
    }
};