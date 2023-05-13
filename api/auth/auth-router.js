const express = require("express");
const bcrypt = require("bcryptjs");
const router = express.Router();
const {
  checkUsernameFree,
  checkUsernameExists,
  checkPasswordLength,
} = require("./auth-middleware");
const User = require("../users/users-model");

router.post(
  "/register",
  checkUsernameFree,
  checkPasswordLength,
  async (req, res, next) => {
    try {
      const { username, password } = req.body;
      const hash = bcrypt.hashSync(password, 8);
      const newUser = { username, password: hash };
      const result = await User.add(newUser);
      res.status(201).json(result);
    } catch (err) {
      next(err);
    }
  }
);

router.post("/login", checkUsernameExists, (req, res, next) => {
  const { password } = req.body;
  if (bcrypt.compareSync(password, req.user.password)) {
    req.session.user = req.user;
    res.json({ message: `Welcome ${req.user.username}!` });
  } else {
    next({
      status: 401,
      message: "invalid credentials",
    });
  }
});

router.get("/logout", (req, res, next) => {
  if (req.session.user) {
    req.session.destroy((err) => {
      if (err) {
        res.json({ message: "no session" });
      } else {
        res.set(
          "Set-Cookie",
          "chocolatechip=; SameSite=Strict; Path=/; Expires=Thu, 01 Jan 1970 00:00:00"
        );
        res.json({ message: "logged out" });
      }
    });
  } else {
    next(res.json({ message: "no session" }));
  }
});

/**
  3 [GET] /api/auth/logout

  response for logged-in users:
  status 200
  {
    "message": "logged out"
  }

  response for not-logged-in users:
  status 200
  {
    "message": "no session"
  }
 */

// Don't forget to add the router to the `exports` object so it can be required in other modules
module.exports = router;
