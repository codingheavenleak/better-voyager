const express = require('express');
const crypto = require('crypto');
const router = express.Router();

router.get('/', (req, res) => {
    const encryptionKey = crypto.randomBytes(32).toString('hex'); // 256-bit key
    res.status(200).json({ encryptionKey });
});

module.exports = router;
