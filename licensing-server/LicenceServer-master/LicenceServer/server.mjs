import http from 'http';
import express from 'express';
import 'dotenv/config';
import axios from 'axios';
import { LexActivator, PermissionFlags, LexStatusCodes } from '@cryptlex/lexactivator';
import chalk from 'chalk';
import { storeActivation } from './database.js';

const app = express();
const PORT = process.env.PORT || 7850;

// Load configuration from environment variables
const PRODUCT_DATA = process.env.PRODUCT_DATA;
const PRODUCT_ID = process.env.PRODUCT_ID;
const XOR_KEY = process.env.XOR_KEY;
const CRYPTLEX_API_KEY = process.env.CRYPTLEX_API_KEY;
const DISCORD_WEBHOOK = process.env.DISCORD_WEBHOOK;
const CRYPTLEX_API_URL = "https://api.eu.cryptlex.com";

LexActivator.SetProductData(PRODUCT_DATA);
LexActivator.SetProductId(PRODUCT_ID, 1);

function xorDecrypt(input, key) {
    let output = '';
    for (let i = 0; i < input.length; i++) {
        output += String.fromCharCode(input.charCodeAt(i) ^ key.charCodeAt(i % key.length));
    }
    return output;
}

function hexToBytes(hex) {
    const bytes = [];
    for (let i = 0; i < hex.length; i += 2) {
        bytes.push(parseInt(hex.substr(i, 2), 16));
    }
    return String.fromCharCode.apply(String, bytes);
}

function logRequest(ip, secretKey, clientInfo) {
    const now = new Date();
    console.log(chalk.blue(`\n[${now.toISOString()}] New Request:`));
    console.log(chalk.blue(`  IP: ${ip}`));
    console.log(chalk.blue(`  SECRET_KEY: ${secretKey}`));
    console.log(chalk.blue(`  Client Info: ${JSON.stringify(clientInfo)}`));
}

function activate(licenseKey) {
    try {
        console.log(chalk.cyan('\nActivation Process:'));
        LexActivator.SetLicenseKey(licenseKey);
        LexActivator.SetActivationMetadata('key1', 'value1');
        const status = LexActivator.ActivateLicense();

        if (status === LexStatusCodes.LA_OK) {
            console.log(chalk.green('  License activated successfully!'));
            return true;
        } else {
            console.log(chalk.yellow('  License activation failed:', status));
            return false;
        }
    } catch (error) {
        console.log(chalk.red('  License activation error:', error.message));
        return false;
    }
}

function verify() {
    try {
        console.log(chalk.magenta('\nVerification Process:'));
        const status = LexActivator.IsLicenseGenuine();
        if (status === LexStatusCodes.LA_OK) {
            console.log(chalk.green('  License is genuinely activated!'));
            return true;
        } else {
            console.log(chalk.red('  License verification failed:', status));
            return false;
        }
    } catch (error) {
        console.log(chalk.red('  License verification error:', error.message));
        return false;
    }
}

async function getLicenseId(licenseKey) {
    console.log(chalk.yellow(`\n[DEBUG] Retrieving License ID for Key: ${licenseKey}`));

    try {
        const response = await axios.get(`${CRYPTLEX_API_URL}/v3/licenses?key=${licenseKey}`, {
            headers: { 'Authorization': `Bearer ${CRYPTLEX_API_KEY}` }
        });

        if (response.data.length > 0) {
            const licenseId = response.data[0].id;
            console.log(chalk.green(`[DEBUG] License ID: ${licenseId}`));
            return licenseId;
        } else {
            console.log(chalk.red(`[ERROR] No License ID found for key: ${licenseKey}`));
            return null;
        }
    } catch (error) {
        console.log(chalk.red(`[ERROR] Failed to retrieve License ID:`), error.message);
        return null;
    }
}

async function sendDiscordEmbed(clientInfo, licenseKey) {
    if (!DISCORD_WEBHOOK) {
        console.log(chalk.red(`[ERROR] DISCORD_WEBHOOK not defined in .env`));
        return;
    }

    const embed = {
        embeds: [
            {
                title: "New API Activation",
                color: 3447003,
                fields: [
                    {
                        name: "License Key",
                        value: licenseKey,
                        inline: false
                    },
                    {
                        name: "Client DateTime",
                        value: clientInfo.datetime || "Unknown",
                        inline: false
                    },
                    {
                        name: "Client IP Info",
                        value: JSON.stringify(clientInfo.ip_info, null, 2) || "Unknown",
                        inline: false
                    }
                ],
                timestamp: new Date().toISOString()
            }
        ]
    };

    try {
        await axios.post(DISCORD_WEBHOOK, embed, { headers: { "Content-Type": "application/json" } });
        console.log(chalk.green(`[INFO] Activation data sent to Discord webhook.`));
    } catch (error) {
        console.log(chalk.red(`[ERROR] Failed to send data to Discord: ${error.message}`));
    }
}

app.use(express.json());

app.post('/api/validate', async (req, res) => {
    const startTime = Date.now();
    const secretKey = xorDecrypt(hexToBytes(req.body.SECRET_KEY), XOR_KEY);
    const clientInfo = req.body.CLIENT_INFO ? JSON.parse(req.body.CLIENT_INFO) : {};
    logRequest(req.ip, secretKey, clientInfo);

    let success = false;

    if (activate(secretKey) && verify()) {
        success = true;
        await sendDiscordEmbed(clientInfo, secretKey);
    }

    const totalTime = (Date.now() - startTime) / 1000;
    console.log(chalk.green(`\n[INFO] Request completed in ${totalTime}s`));
    res.json({ success, timeTaken: totalTime });
});
const server = http.createServer(app);
server.timeout = 190 * 1000;

server.listen(PORT, () => {
    console.log(chalk.green(`\n[INFO] Server running at http://localhost:${PORT}`));
});

