const User = require('../models/user.model'); 
const jwt = require('jsonwebtoken');
const expressJwt = require('express-jwt');
const config = require('../config/db.config'); 

const signIn = async (req, res) => {
  try {
    const user = await User.findOne({ email: req.body.email });
    if (!user) {
      return res.status(401).json({ error: "User not found" });
    }

    if (!user.authenticate(req.body.password)) {
      return res.status(401).json({ error: "Email and password don't match." });
    }

    const token = user.generateJwt();

    res.cookie('t', token, { expire: new Date() + 9999 });

    return res.json({
      token,
      user: {
        _id: user._id,
        name: user.name,
        email: user.email
      }
    });
  } catch (err) {
    return res.status(401).json({ error: "Could not sign in" });
  }
};

const signOut = (req, res) => {
  res.clearCookie('t');
  return res.status(200).json({ message: "Signed out successfully!" });
};

const hasAuthorization = (req, res, next) => {
  const authorized = req.profile && req.auth && String(req.profile._id) === String(req.auth._id);
  if (!authorized) {
    return res.status(403).json({ error: "User is not authorized" });
  }
  next();
};

module.exports = { signIn, signOut, hasAuthorization };
