const express = require('express');
const fs = require('fs');
const path = require('path');
const jwt = require('jsonwebtoken');
const http = require('http'); 
const app = express();

// rsa
const privateKey = fs.readFileSync(path.join(__dirname, 'private.pem'));
const publicKey = fs.readFileSync(path.join(__dirname, 'public.pem'));

// paths
const streamDirectory = path.join(__dirname, 'Stream');

// imports
const encryptKey = require('./encrypt-key');
const getArray = require('./get-array');
const getJwt = require('./get-jwt');
const sendPrivateKey = require('./send-privatekey');

// basic health check to see if server = active
app.get('/health', (req, res) => {
    res.status(200).json({ status: 'OK', message: 'Server is online and operational.' });
});

app.use('/encrypt-key', encryptKey);
app.use('/get-array', getArray);
app.use('/get-jwt', getJwt);
app.get('/send-privatekey', sendPrivateKey);

const PORT = 3000;
const server = http.createServer(app);

server.timeout = 190 * 1000; 

server.listen(PORT, () => {
    console.log(`[INFO] Server running at http://localhost:${PORT}`);
});