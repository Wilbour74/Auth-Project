const express = require('express');
const path = require('path');
const router = express.Router();
const isAuthenticated = require('../middlewares/authCheck');

router.get('/bat-computer', isAuthenticated, (req, res) => {
  res.sendFile(path.join(__dirname, '../views', 'bat-computer.html'));
});

module.exports = router;