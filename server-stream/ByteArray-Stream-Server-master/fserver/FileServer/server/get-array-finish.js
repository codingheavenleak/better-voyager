module.exports = (req, res) => {
    console.log('[INFO] Received request to finalize get-array.');

    const preview = req.body.preview;

    if (!preview) {
        console.error('[ERROR] No preview data received.');
        return res.status(400).send('Invalid request: No preview data provided.');
    }

    console.log(`[INFO] First 4 characters of encrypted data: ${preview}`);
    res.status(200).send('get-array-finish executed successfully.');
};
