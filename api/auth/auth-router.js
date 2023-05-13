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
      const hash = bcrypt.hashSync(password, 12);
      const newUser = { username, password: hash };
      const result = await User.add(newUser);
      res.status(200).json({
        user_id: result.user_id,
        username: result.username,
      });
    } catch (err) {
      next(err);
    }
  }
);

router.post("/login", checkUsernameExists, async (req, res, next) => {
  try {
    const { username, password } = req.body;
    const [user] = await User.findBy({ username });
    if (user && bcrypt.compareSync(password, user.password)) {
      req.session.user = user;
      res.json({ message: `Welcome ${user.username}!` });
    } else {
      next({
        status: 401,
        message: "invalid credentials",
      });
    }
  } catch (err) {
    next(err);
  }
});

router.get("/logout", (req, res, next) => {
  if (req.session.user) {
    res.session.destroy((err) => {
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
