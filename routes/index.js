const router = require("express").Router();
const bcryptjs = require("bcryptjs")
const saltRounds = 10
const User = require('../models/User.model');

/* GET home page */
router.get("/", (req, res, next) => {
  res.render("index");
});

/* GET signup page */
router.get("/signup", (req, res, next) => {
  res.render("auth/signup");
});

/* POST signup page */
router.post("/signup", (req, res, next) => {
  const { username, email, password } = req.body;
 
  bcryptjs
    .genSalt(saltRounds)
    .then(salt => bcryptjs.hash(password, salt))
    .then(hashedPassword => {
      return User.create({
        username: username,
        email: email,
        passwordHash: hashedPassword
      });
    })
    .then(userFromDB => {
      res.redirect('/userProfile/' + userFromDB.username);
    })
    .catch(error => next(error));
});

router.get('/userProfile/:username', (req, res) => {
  const username = req.params.username
  res.render('users/user-profile', {username})
});

module.exports = router;
