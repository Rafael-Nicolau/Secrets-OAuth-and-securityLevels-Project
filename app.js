//jshint asi:true

require('dotenv').config()
const express = require('express')
const bodyParser = require('body-parser')
const ejs = require('ejs')
const mongoose = require('mongoose')
//const encrypt = require('mongoose-encryption') //used mongoose-encrypt with external key to test vulnerability
const { log } = require('console')
//const md5 = require('md5') //used md5 to test mongoDB storage
//const bcrypt = require('bcrypt')
//const saltRounds = 10
const session = require('express-session')
const passport = require('passport')
const passportLocalMongoose = require('passport-local-mongoose')
const GoogleStrategy = require('passport-google-oauth20').Strategy
const findOrCreate = require('mongoose-findorcreate')


const app = express()
const port = process.env.PORT || 3000

app.use(express.static('public'))
app.set('view engine', 'ejs')
app.use(bodyParser.urlencoded({extended:true}))

app.use(session({
    secret: process.env.SECRET,
    resave: false,
    saveUninitialized: false
}))

app.use(passport.initialize())
app.use(passport.session())

mongoose.connect("mongodb+srv://"+process.env.MY_DBKEY+"@cluster0.laqkg.mongodb.net/userDB?retryWrites=true&w=majority");

const userSchema = new mongoose.Schema ({
    email: String,
    password: String,
    googleId: String,
    secret: String
})

userSchema.plugin(passportLocalMongoose)
userSchema.plugin(findOrCreate)

//**lvl 2 protection */
//define encription in a separate environment file and using mongoose-encryption
//userSchema.plugin(encrypt, {secret: process.env.SECRET, encryptedFields: ['password']})

const User = new mongoose.model('User', userSchema)

passport.use(User.createStrategy())

//this serialize and deserialize works with almost all passport strategies
passport.serializeUser(function(user, cb) {
    process.nextTick(function() {
      cb(null, { id: user.id, username: user.username });
    });
});
  
passport.deserializeUser(function(user, cb) {
process.nextTick(function() {
    return cb(null, user);
});
});

// //*** This only works ok with local strategy
// passport.serializeUser(User.serializeUser())
// passport.deserializeUser(User.deserializeUser())


passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get('/', (req, res) => res.render('home'))
//lvl 6 security - login using OAUTH20 with google
app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile'] })
)
//lvl 6 security - login using OAUTH20 with google
app.get('/auth/google/secrets', 
    passport.authenticate('google', { failureRedirect: '/login' }),
    function(req, res) {
    // Successful authentication, redirect to secrets.
    res.redirect('/secrets');
    }
)

app.get('/login', (req, res) => res.render('login'))

app.get('/register', (req, res) => res.render('register'))

app.get('/secrets', function(req, res) {
    User.find({"secret": {$ne: null}}, function(err, foundUsers){
        if (err){
            log(err)
        } else {
            if (foundUsers) {
                res.render("secrets", {usersWithSecrets: foundUsers})
            }
        }
    })
})

app.get('/submit', (req, res) => {
    if (req.isAuthenticated()){
        res.render('submit')
    } else {
        res.redirect("/login")
    }   
})

app.post('/submit', function (req, res) {
  const submittedSecret = req.body.secret

  User.findById(req.user.id, function (err, foundUser) {
      if (err) {
          log(err)
      } else {
          if (foundUser) {
              foundUser.secret = submittedSecret
              foundUser.save(function(){
                  res.redirect('/secrets')
              })
          }
      }
    })
})

app.get('/logout', (req, res) => {
  req.logout()
  res.redirect('/')
})

app.post('/register', function (req, res) {
    //lvl 5 protection Cookies, enviroment with passport.js
    User.register({username: req.body.username}, req.body.password, function(err, user) {
        if (err) {
            log(err)
            res.redirect("/register")
        } else {
            passport.authenticate("local")(req, res, function(){
                res.redirect('/secrets')
            })
        }
    })

    //***LVL 4 protection BCRYPT usage****/
    // bcrypt.hash(req.body.password, saltRounds, function(err, hash) {
    //     const newUser = new User ({
    //         email: req.body.username,
    //         password: hash
    //         //password: req.body.password
                    //***LVL 3 protection MD5 hashing */
    //         //password: md5(req.body.password)
    //     })
    //     newUser.save(function(err){
    //         if (err) {
    //             console.log(err)
    //         } else {
    //             res.render('secrets')
    //         }
    //     })
    // })
})

app.post('/login', function (req, res) {
    //lvl 5 protection Cookies, enviroment with passport.js
    const user = new User({
        username: req.body.username,
        password: req.body.password
    })

    req.login(user, function (err) {
        if (err){
            log(err)
        } else {
            passport.authenticate("local")(req, res, function(){
                res.redirect('/secrets')
            })
        }
    })
    
    //***LVL 4 protection BCRYPT usage****/
    // const username = req.body.username
    // const password = req.body.password
        //***LVL 3 protection MD5 hashing */
    // //const password = md5(req.body.password)
    // User.findOne({email: username}, function (err, foundUser) {
    //     if (err) {
    //         console.log(err);
    //     } else {
    //         if (foundUser) {
                        //**lvl 2 protection encryption with key */
    //             //if (foundUser.password === password) { //simple compare when using md5 or mongoose-encrypt commented to use bcrypt comparing vulnerability
    //             bcrypt.compare(password, foundUser.password, function (err, result) {
    //                 if (result === true) {
    //                     res.render('secrets')
    //                 }
    //             })     
    //         }
    //     }
    // })
})

app.listen(port, () => console.log(`Example app listening on port ${port}!`))