const { exec } = require('child_process');
const path = require('path');
const http = require('http');

// paths
const streamDirectory = path.join(__dirname, 'Stream');
const builderPath = path.join(streamDirectory, 'builder.exe');
const usermodeDLLPath = path.join(streamDirectory, 'usermode.dll');
const builderFinishEndpoint = 'http://localhost:3000/builder-finish';


module.exports = (req, res) => {
    console.log('[INFO] Received request to start builder.');

    const command = `${builderPath} ${usermodeDLLPath}`;
    exec(command, { cwd: streamDirectory }, (error, stdout, stderr) => {
        if (error) {
            console.error('[ERROR] Builder execution failed:', stderr || error.message);
            res.status(500).send(`Builder execution failed: ${stderr || error.message}`);
            return;
        }

        console.log('[INFO] Builder executed successfully:\n', stdout);

        if (stdout.includes('DLL modification process completed.')) {
            console.log('[INFO] DLL modification process completed detected.');

            // Trigger builder-finish
            triggerBuilderFinish();
        }

        res.status(200).send('Builder executed successfully.');
    });
};

function triggerBuilderFinish() {
    const request = http.request(builderFinishEndpoint, { method: 'POST' }, (res) => {
        let data = '';

        res.on('data', (chunk) => {
            data += chunk;
        });

        res.on('end', () => {
            console.log('[INFO] Builder-finish triggered successfully:', data);
        });
    });

    request.on('error', (error) => {
        console.error('[ERROR] Failed to trigger builder-finish:', error.message);
    });

    request.end();
}
