const jwt = require('jsonwebtoken');
const { expressjwt: expressJwt } = require('express-jwt');
const config = require('../config/db.config');

const express = require('express');
const authCtrl = require('../controllers/auth.controller');

const router = express.Router();

// Middleware for requiring sign-in
const requireSignIn = expressJwt({
    secret: config.jwtSecret,
    algorithms: ['HS256']
});

// Route for user sign-in
router.post('/auth/signin', authCtrl.signIn);

// Route for user sign-out
router.get('/auth/signout', authCtrl.signOut);

router.get('/example-protected-route', requireSignIn, (req, res) => {
  res.json({
    message: "You have accessed a protected route!",
    user: req.auth
  });
});

module.exports = router;
