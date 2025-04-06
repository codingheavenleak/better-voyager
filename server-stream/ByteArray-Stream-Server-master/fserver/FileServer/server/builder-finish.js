const express = require("express");
const router = express.Router();

router.post("/", (req, res) => {
  console.log("[INFO] Builder finished.");
  res.send("Builder finished successfully.");
});

module.exports = router;
