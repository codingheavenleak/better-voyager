const { exec } = require('child_process');
const path = require('path');
const http = require('http');

// paths
const streamDirectory = path.join(__dirname, 'Stream');
const bytearrayPath = path.join(streamDirectory, 'bytearray.exe');
const uniqueDLLPath = path.join(streamDirectory, 'unique_um.dll');
const bytearrayFinishEndpoint = 'http://localhost:3000/bytearray-finish';

// Handle POST request to start bytearray generation
module.exports = (req, res) => {
    console.log('[INFO] Received request to start bytearray generation.');

    // Execute bytearray command
    const command = `${bytearrayPath} ${uniqueDLLPath}`;
    exec(command, { cwd: streamDirectory }, (error, stdout, stderr) => {
        if (error) {
            console.error('[ERROR] Bytearray execution failed:', stderr || error.message);
            res.status(500).send(`Bytearray execution failed: ${stderr || error.message}`);
            return;
        }

        console.log('[INFO] Bytearray executed successfully:\n', stdout);

        // Check if the output contains 'DLL successfully converted to byte array and saved as um.h'
        if (stdout.includes('DLL successfully converted to byte array and saved as um.h')) {
            console.log('[INFO] Bytearray generation completed successfully.');

        } else {
            console.error('[ERROR] Bytearray process did not complete successfully.');
            res.status(500).send('Bytearray process did not complete successfully.');
            return;
        }

        res.status(200).send('Bytearray executed successfully.');
    });
};


