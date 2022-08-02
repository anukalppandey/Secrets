//"mongoose-encryption" for encryption and "dotenv" for hiding encryption key
//"md5" for easy hashing
//"bcrypt" for good hashing
// const bcrypt = require("bcrypt");
// const saltRounds = 10;
require("dotenv").config();
const express = require("express");
const ejs = require("ejs");
const bp = require("body-parser");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const findOrCreate = require("mongoose-findorcreate");
const e = require("express");


const app = express();

mongoose.connect("mongodb://localhost:27017/userDB", (err) => {
    if (err) throw err;
    else console.log("Connection established successfully");
});

app.use(
    session({
        secret: process.env.SEC,
        resave: false,
        saveUninitialized: false,
    })
); //
app.use(passport.initialize()); //
app.use(passport.session()); //

app.use(bp.urlencoded({ extended: true }));
app.set("view engine", "ejs");
app.use(express.static("public"));

const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String,
    facebookId: String,
    secret: String
});
userSchema.plugin(passportLocalMongoose); //
userSchema.plugin(findOrCreate);
const User = new mongoose.model("user", userSchema);
passport.use(User.createStrategy()); //

// passport.serializeUser(User.serializeUser()); //
// passport.deserializeUser(User.deserializeUser()); //
//Authentication using Google Account aka GMAIL
passport.use(
    new GoogleStrategy(
        {
            clientID: process.env.CLIENT_ID,
            clientSecret: process.env.CLIENT_SECRET,
            callbackURL: "http://localhost:3000/auth/google/secrets",
        },
        function (accessToken, refreshToken, profile, cb) {
            User.findOrCreate({ googleId: profile.id }, function (err, user) {
                return cb(err, user);
            });
        }
    )
);


passport.serializeUser((user, done)=>{
    done(null,user);
});
passport.deserializeUser((id, done)=>{
    User.findById(id, (err,user)=>{
        done(err, user);
    })
});

app.get("/", (req, res) => {
    res.render("home");
});

app.get("/auth/google", 
    passport.authenticate("google", {scope: ["profile"]})
);

app.get("/auth/google/secrets",
    passport.authenticate("google", {failureRedirect: "/login"}),
    (req,res)=>{
        res.redirect("/secrets");
    }
);

app.get("/login", (req, res) => {
    res.render("login");
});

app.get("/register", (req, res) => {
    res.render("register");
});

app.get("/secrets", (req, res) => {
    User.find({"secret": {$ne: null}}, (err, foundUsers)=>{
        if(err) console.log(err);
        else {
            if(foundUsers){
                res.render("secrets", {usersWithSecrets: foundUsers});
            }
        }
    })
});

app.post("/register", (req, res) => {
    User.register(
        { username: req.body.username },
        req.body.password,
        (err, user) => {
            if (err) {
                console.log(err);
                res.redirect("/register");
            } else {
                passport.authenticate("local")(req, res, () => {
                    res.redirect("/secrets");
                });
            }
        }
    );
});

app.post("/login", (req, res) => {
    const user = new User({
        username: req.body.username,
        password: req.body.passport,
    });
    req.login(user, (err) => {
        if (err) {
            console.log(err);
        } else {
            passport.authenticate("local")(req, res, () => {
                res.redirect("/secrets");
            });
        }
    });
});

app.get("/submit", (req, res) => {
    if (req.isAuthenticated()) {
        res.render("submit");
    } else {
        res.redirect("/login");
    }
});

app.post("/submit", (req,res)=>{
    const submittedSecret = req.body.secret;
    User.findById(req.user.id,(err, foundUser)=>{
        if(err) console.log(err);
        else{
            if(foundUser){
                // foundUser.secret.push(submittedSecret);
                foundUser.secret = submittedSecret;
                foundUser.save(()=>{
                    res.redirect("/secrets");
                });
            }
        }
    })
});

app.get("/logout", (req, res) => {
    req.logout((err) => {
        if (err) console.log(err);
        else res.redirect("/");
    });
});

app.listen(3000, () => {
    console.log("Server started at port 3000");
});

// Using Bcrpyt package to hash the passwords-------------------------------
// app.post("/register", (req, res) => {
//     bcrypt.hash(req.body.password, saltRounds, (err, hash) => {
//         if (err) {
//             console.log(err);
//         } else {
//             const newUser = new User({
//                 email: req.body.username,
//                 password: hash,
//             });
//             newUser.save((err) => {
//                 if (err) console.log(err);
//                 else res.render("secrets");
//             });
//         }
//     });
// });

// app.post("/login", (req, res) => {
//     User.findOne({ email: req.body.username }, (err, foundUser) => {
//         if (err) console.log(err);
//         else {
//             if (foundUser) {
//                 bcrypt.compare(req.body.password, foundUser.password, (err, result) => {
//                     if (err) console.log(err);
//                     else {
//                         if (result === true) {
//                             res.render("secrets");
//                         } else console.log("Bad Credentials");
//                     }
//                 });
//             } else console.log("Bad Credentials");
//         }
//     });
// });
