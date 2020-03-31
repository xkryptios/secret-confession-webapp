require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const findOrCreate = require("mongoose-findorcreate");
const FacebookStrategy = require("passport-facebook").Strategy;
const MongoStore = require("connect-mongo")(session);

const app = express();
app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({ extended: true }));
//confirgure express session

//connnet to mongodb
mongoose.connect(process.env.MONGOSERVER, {
	useNewUrlParser: true,
	useUnifiedTopology: true
});

app.use(
	session({
		//this could be any string, not sure what its for
		secret: "Our little secret.",
		resave: false,
		saveUninitialized: false,
		store: new MongoStore({ mongooseConnection: mongoose.connection })
	})
);

//initialise passports and allow passport to use session
app.use(passport.initialize());
app.use(passport.session());

//create a new mongoose schema object and create a mongoose model
//need to include every data type from OAuth
const userSchema = new mongoose.Schema({
	username: String,
	password: String,
	googleId: String,
	facebookId: String,
	secrets: String
});
//allow schema Model to create local strategy
userSchema.plugin(passportLocalMongoose);
//allow this schema Model to be found or created when using oAuth
userSchema.plugin(findOrCreate);

const User = mongoose.model("User", userSchema);

passport.serializeUser(function(user, done) {
	done(null, user.id);
});
passport.deserializeUser(function(id, done) {
	User.findById(id, function(err, user) {
		done(err, user);
	});
});

//create local strategy or make use of OAuth strategies
passport.use(User.createStrategy());

//setup strategy
//setup session to take in acess token and profile upon approval from fb
passport.use(
	new GoogleStrategy(
		{
			clientID: process.env.GOOGLE_CLIENT_ID,
			clientSecret: process.env.GOOGLE_CLIENT_SECRET,
			callbackURL: "http://localhost:3000/auth/google/secrets"
		},
		function(accessToken, refreshToken, profile, cb) {
			User.findOrCreate({ googleId: profile.id }, function(err, user) {
				return cb(err, user);
			});
		}
	)
);

//setup fb strategy
//setup session to take in acess token and profile upon approval from fb
passport.use(
	new FacebookStrategy(
		{
			clientID: process.env.FACEBOOK_APP_ID,
			clientSecret: process.env.FACEBOOK_APP_SECRET,
			callbackURL: "http://localhost:3000/auth/facebook/secrets"
		},
		function(accessToken, refreshToken, profile, done) {
			User.findOrCreate({ facebookId: profile.id }, function(err, user) {
				if (err) {
					return done(err);
				}
				done(null, user);
			});
		}
	)
);

//GET / POST REQUESTS
app.post("/register", function(req, res) {
	User.register({ username: req.body.username }, req.body.password, function(
		err,
		user
	) {
		if (err) {
			console.log(err);
			res.redirect("/register");
		} else {
			passport.authenticate("local")(req, res, function() {
				res.redirect("/secrets");
			});
		}
	});
});

//do post for login
app.post("/login", function(req, res) {
	const user = new User({
		username: req.body.username,
		password: req.body.password
	});
	req.login(user, function(err) {
		if (err) {
			res.redirect("/login");
		} else {
			passport.authenticate("local")(req, res, function() {
				res.redirect("/secrets");
			});
		}
	});
});

app.get("/", function(req, res) {
	res.render("home");
});
//directs user to signin at google, ask google for scope upon completion
app.get(
	"/auth/google",
	passport.authenticate("google", {
		scope: [
			"https://www.googleapis.com/auth/plus.login",
			"https://www.googleapis.com/auth/userinfo.email"
		]
	})
);
//google redirects user back to secrets page upon successful verification
app.get(
	"/auth/google/secrets",
	passport.authenticate("google", { failureRedirect: "/login" }),
	function(req, res) {
		// Successful authentication, redirect secrets.
		res.redirect("/secrets");
	}
);

// Redirect the user to Facebook for authentication.  When complete,
// Facebook will redirect the user back to the application at
//     /auth/facebook/callback
app.get("/auth/facebook", passport.authenticate("facebook"));

// Facebook will redirect the user to this URL after approval.  Finish the
// authentication process by attempting to obtain an access token.  If
// access was granted, the user will be logged in.  Otherwise,
// authentication has failed.
app.get(
	"/auth/facebook/secrets",
	passport.authenticate("facebook", {
		successRedirect: "/secrets",
		failureRedirect: "/login"
	})
);

app.get("/login", function(req, res) {
	res.render("login");
});
app.get("/register", function(req, res) {
	res.render("register");
});

app.get("/logout", function(req, res) {
	req.logout();
	res.redirect("/");
});

//when user who logged in who wants to submit a secret
//check if user is authenticated, if not send to login screen
app.get("/submit", function(req, res) {
	if (req.isAuthenticated()) {
		res.render("submit");
	} else {
		res.redirect("/login");
	}
});

//when user submits a new secret checking for id of user loged in
//add secret to user's secret list
app.post("/submit", function(req, res) {
	const newsecret = req.body.secret;
	User.findById(req.user._id, function(err, userfound) {
		if (!err) {
			userfound.secrets = newsecret;
			userfound.save(function() {
				res.redirect("/secrets");
			});
		}
	});
});

//secret is a page opened for all
app.get("/secrets", function(req, res) {
	User.find({ secrets: { $ne: null } }, function(err, result) {
		console.log(result);
		res.render("secrets", { usersWithSecret: result });
	});
});

app.listen(process.env.PORT || 3000, function() {
	console.log("server began at port 3000");
});
