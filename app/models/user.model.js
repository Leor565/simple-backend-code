const mongoose = require("mongoose");
const bcrypt = require("bcrypt");

var schema = mongoose.Schema({
    name: String,
    email: {
        type: String,
        trim: true,
        unique: 'Email already exists',
        match: [/.+\@.+\..+/, 'Please fill a valid email address'],
        required: 'Email is required'
      },
    password: String, // Store the hashed password
    salt: String,     // Store the salt
    created: {
        type: Date,
        default: Date.now
      },
      updated: {
        type: Date,
        default: Date.now
      }
});

schema.method("toJSON", function () {
    const { __v, _id, salt, ...object } = this.toObject();
    object.id = _id;

    return object;
});

// Hash the password before saving to the database
schema.pre("save", async function (next) {
    const user = this;
    if (!user.isModified("password")) return next();

    const saltRounds = 10; // Adjust the number of salt rounds as needed
    const salt = await bcrypt.genSalt(saltRounds);
    const hashedPassword = await bcrypt.hash(user.password, salt);

    user.password = hashedPassword;
    user.salt = salt;
    next();
});

const Users = mongoose.model("user", schema);

module.exports = Users;
