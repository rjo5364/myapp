//dependencies
const express = require('express'); // This is importing the Express framework
const mongoose = require('mongoose'); // This is importing Mongoose for MongoDB connection
const passport = require('passport'); // This is importing Passport for authentication
const session = require('express-session'); // This is importing Express session management
const bodyParser = require('body-parser'); // This is importing Body-Parser for request body parsing
const axios = require('axios'); // This is importing Axios for HTTP requests
const path = require('path'); // This is importing Path for file path manipulation
const cors = require('cors'); // This is importing CORS for cross-origin resource sharing

// This checks if the app is running in development mode and loads environment variables
if (process.env.NODE_ENV !== 'production') {
  require('dotenv').config();
}

const GoogleStrategy = require('passport-google-oauth20').Strategy; // imports Google OAuth strategy for Passport

const app = express(); // initializing the Express app

// Middleware
app.use(bodyParser.json()); // parses incoming JSON requests
app.use(cors({ 
  origin: 'http://localhost:3000', 
  credentials: true 
})); // enables CORS with settings

// config for session management
app.use(
  session({
    secret: process.env.SESSION_SECRET, 
    resave: false, 
    saveUninitialized: true, 
    cookie: { secure: true }, 
  })
);
app.use(passport.initialize()); // initializes Passport middleware
app.use(passport.session()); // enables Passport session handling

// MongoDB connection
mongoose
  .connect('mongodb://127.0.0.1:27017/myapp', {
    useNewUrlParser: true, // uses the new URL parser
    useUnifiedTopology: true, // enables the new server discovery engine
  })
  .then(() => console.log('Connected to MongoDB')) // logs successful connection
  .catch((err) => console.error('Failed to connect to MongoDB:', err)); // logs connection errors

// User schema
const userSchema = new mongoose.Schema({
  socialId: String, // stores social media ID
  name: String, // stores user name
  email: String, // stores user email
  platform: String, // stores authentication platform
  profilePicture: String, // stores user profile picture URL
});

const User = mongoose.model('User', userSchema); // creates a Mongoose model for users

// Google Strategy
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID, // sets the Google client ID
      clientSecret: process.env.GOOGLE_CLIENT_SECRET, // sets the Google client secret
      callbackURL: 'http://localhost:5000/auth/google/callback', // sets the Google OAuth callback URL
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        let user = await User.findOne({ socialId: profile.id }); // searches for the user in the database

        if (!user) {
          user = new User({
            socialId: profile.id,
            name: profile.displayName,
            email: profile.emails[0].value,
            platform: 'google',
            profilePicture: profile.photos[0]?.value || '',
          });

          await user.save(); // saves the new user to the database
        }

        return done(null, user); // passes the user to Passport
      } catch (err) {
        console.error('Error saving user:', err); // logs errors
        return done(err, null); // passes the error to Passport
      }
    }
  )
);

// Serialize and deserialize user
passport.serializeUser((user, done) => done(null, user.id)); // serializes user by ID
passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id); // finds the user by ID
    done(null, user); // passes the user object to Passport
  } catch (err) {
    done(err, null); // handles errors
  }
});

// Google Routes
app.get(
  '/auth/google',
  passport.authenticate('google', { scope: ['profile', 'email'] }) // starts Google authentication
);

app.get(
  '/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/' }), // handles Google callback
  (req, res) => {
    res.redirect('http://localhost:3000/profile'); // redirects to frontend after login
  }
);

// LinkedIn Routes
app.get('/auth/linkedin', (req, res) => {
  const linkedinAuthURL = `https://www.linkedin.com/oauth/v2/authorization?response_type=code&client_id=${process.env.LINKEDIN_CLIENT_ID}&redirect_uri=${process.env.LINKEDIN_REDIRECT_URI}&scope=openid%20profile%20email`;
  res.redirect(linkedinAuthURL); // redirects to LinkedIn for authentication
});

app.get('/auth/linkedin/callback', async (req, res) => {
  try {
    const code = req.query.code; // retrieves the authorization code

    const tokenResponse = await axios.post(
      'https://www.linkedin.com/oauth/v2/accessToken',
      null,
      {
        params: {
          grant_type: 'authorization_code',
          code: code,
          redirect_uri: process.env.LINKEDIN_REDIRECT_URI,
          client_id: process.env.LINKEDIN_CLIENT_ID,
          client_secret: process.env.LINKEDIN_CLIENT_SECRET,
        },
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      }
    );

    const accessToken = tokenResponse.data.access_token; // extracts the access token

    const profileResponse = await axios.get(
      'https://api.linkedin.com/v2/userinfo',
      {
        headers: {
          Authorization: `Bearer ${accessToken}`,
        },
      }
    );

    const { sub, name, email, picture } = profileResponse.data; // extracts user info

    let user = await User.findOne({ socialId: sub }); // checks if user exists

    if (!user) {
      user = new User({
        socialId: sub,
        name: name,
        email: email || 'No email provided',
        platform: 'linkedin',
        profilePicture: picture || '',
      });

      await user.save(); // saves the new user to the database
    }

    req.login(user, (err) => {
      if (err) {
        console.error('Login error:', err);
        return res.redirect('/'); // handles login errors
      }
      res.redirect('http://localhost:3000/profile'); // redirects to frontend after login
    });
  } catch (err) {
    console.error('LinkedIn authentication error:', err); // logs errors
    res.redirect('/'); // redirects to the homepage on error
  }
});

// Profile Route
app.get('/profile', (req, res) => {
  if (!req.isAuthenticated()) {
    return res.status(401).json({ error: 'Unauthorized' }); // denies access if not authenticated
  }

  res.json({
    name: req.user.name, // sends user name
    email: req.user.email, // sends user email
    profilePicture: req.user.profilePicture, // sends user profile picture
  });
});

// Serve React frontend
app.use(express.static(path.join(__dirname, '../myapp/build'))); // serves static files from React build directory

// Logout Route
app.get('/logout', (req, res) => {
  req.logout((err) => {
    if (err) {
      console.error('Logout error:', err);
      return res.status(500).json({ error: 'Logout error' }); // handles logout errors
    }
    req.session.destroy((destroyErr) => {
      if (destroyErr) {
        console.error('Session destroy error:', destroyErr);
        return res.status(500).json({ error: 'Session destroy error' }); // handles session destroy errors
      }
      res.clearCookie('connect.sid', { path: '/' }); // clears session cookie
      return res.status(200).json({ message: 'Logged out successfully' }); // confirms logout
    });
  });
});

// Wildcard Route
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '../myapp/build', 'index.html')); // serves React app for all other routes
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack); // logs the error stack
  res.status(500).send('Something went wrong!'); // sends error response
});

// Start the server
app.listen(5000, () => {
  console.log(`Server is running on http://localhost:5000`); // starts the server
});