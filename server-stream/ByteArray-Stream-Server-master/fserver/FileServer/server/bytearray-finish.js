const axios = require('axios');

module.exports = (req, res) => {
    console.log('[INFO] Received request to complete bytearray generation.');

    try {
        console.log('[INFO] Automatically triggering get-array endpoint...');
        axios.post('http://localhost:3000/get-array')
            .then(response => {
                console.log('[INFO] get-array triggered successfully:', response.data.message);
            })
            .catch(error => {
                console.error('[ERROR] Failed to trigger get-array endpoint:', error.message);
            });
    } catch (error) {
        console.error('[ERROR] An unexpected error occurred:', error.message);
    }

    res.status(200).send('Bytearray generation completed successfully.');
};
