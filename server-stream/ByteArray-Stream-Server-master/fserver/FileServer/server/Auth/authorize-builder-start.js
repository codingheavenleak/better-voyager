module.exports = (req, res) => {
    console.log('[INFO] Received request to authorize builder start.');

    try {
        console.log('[DEBUG] Authorization process for builder-start initialized.');
        res.status(200).send('Ok! Request Authorized');
        console.log('[INFO] Builder-start request authorized successfully.');
    } catch (error) {
        console.error('[ERROR] Failed to authorize builder start:', error.message);
        res.status(500).send('Authorization Failed');
    }
};
