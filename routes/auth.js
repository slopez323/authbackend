var express = require("express");
var router = express.Router();
const bcrypt = require("bcryptjs");
const { uuid } = require("uuidv4");
const { blogsDB } = require("../mongo");
const dotenv = require("dotenv");
const jwt = require("jsonwebtoken");
dotenv.config();

const createUser = async (username, passwordHash) => {
  try {
    const collection = await blogsDB().collection("users");
    const user = {
      username,
      password: passwordHash,
      uid: uuid(),
    };

    await collection.insertOne(user);
    return true;
  } catch (e) {
    console.error(e);
    return false;
  }
};

router.post("/register-user", async function (req, res, next) {
  try {
    const username = req.body.username;
    const password = req.body.password;

    const saltRounds = 5;

    const salt = await bcrypt.genSalt(saltRounds);
    const hash = await bcrypt.hash(password, salt);
    const userSaveSuccess = await createUser(username, hash);

    res.json({ success: userSaveSuccess });
  } catch (e) {
    console.error(e);
    res.json({ success: false });
  }
});

router.post("/login-user", async function (req, res, next) {
  try {
    const collection = await blogsDB().collection("users");
    const user = await collection.findOne({ username: req.body.username });

    const match = await bcrypt.compare(req.body.password, user.password);

    const jwtSecretKey = process.env.JWT_SECRET_KEY;
    const data = {
      time: new Date(),
      userId: user.uid,
      scope: user.username.includes("codeimmersives.com") ? "admin" : "user",
    };
    const token = jwt.sign(data, jwtSecretKey);

    res.json({ success: match, token });
  } catch (e) {
    console.error(e);
    res.json({ success: false });
  }
});

router.get("/validate-token", function (req, res, next) {
  const tokenHeaderKey = process.env.TOKEN_HEADER_KEY;
  const jwtSecretKey = process.env.JWT_SECRET_KEY;

  try {
    const token = req.header(tokenHeaderKey);

    const verified = jwt.verify(token, jwtSecretKey);

    if (verified && verified.scope === "admin") {
      return res.json({
        success: true,
        message: "Speak 'Friend' and enter...",
      });
    }
    if (verified && verified.scope === "user") {
      return res.json({ success: true, message: "You shall not pass!" });
    }

    throw Error("Access Denied");
  } catch (error) {
    // Access Denied
    return res.status(401).json({ success: true, message: String(error) });
  }
});

module.exports = router;
