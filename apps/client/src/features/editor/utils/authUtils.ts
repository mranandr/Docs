import express from 'express';
import session from 'express-session';
import passport from 'passport';
import { Strategy as OIDCStrategy } from 'passport-azure-ad';
import jwt, { JwtPayload } from 'jsonwebtoken';
import dotenv from 'dotenv';
import axios from 'axios';

dotenv.config();

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Session setup (required for passport)
app.use(session({ secret: 'your_secret_key', resave: false, saveUninitialized: true }));
app.use(passport.initialize());
app.use(passport.session());

// OIDC Strategy for Azure Authentication
passport.use(
  new OIDCStrategy(
    {
      identityMetadata: `https://login.microsoftonline.com/${process.env.AZURE_TENANT_ID}/v2.0/.well-known/openid-configuration`,
      clientID: process.env.AZURE_CLIENT_ID!,
      clientSecret: process.env.AZURE_CLIENT_SECRET!,
      responseType: 'code',
      responseMode: 'query',
      redirectUrl: process.env.REDIRECT_URL!,
      allowHttpForRedirectUrl: process.env.NODE_ENV !== 'production',
      scope: ['openid', 'profile', 'email'],
      passReqToCallback: false, 
    },
    (token, done) => {
      done(null, token);
    }
  )
);

passport.serializeUser((user: any, done) => {
  done(null, user);
});

passport.deserializeUser((user: any, done) => {
  done(null, user);
});

app.get('/login', passport.authenticate('azuread-openidconnect', { failureRedirect: '/' }));

app.get(
  '/auth/callback',
  passport.authenticate('azuread-openidconnect', { failureRedirect: '/' }),
  (req, res) => {
    res.redirect('/home');
  }
);

app.get('/home', (req, res) => {
  if (!req.isAuthenticated()) {
    return res.redirect('/login');
  }
  res.json(req.user);
});

export const checkJWT = (token: string): boolean => {
  try {
    jwt.verify(token, process.env.JWT_SECRET || '');
    return true; 
  } catch (error) {
    console.error('Invalid token', error);
    return false;
  }
};

export const loginWithAzure = () => {
  const redirectUrl = process.env.REDIRECT_URL || 'http://localhost:3000';
  window.location.href = `${redirectUrl}/auth/callback`; 
};

export const authenticateUserWithJWT = async (email: string, password: string): Promise<string> => {
  try {
    const response = await axios.post('/api/auth/login', { email, password });
    return response.data.token; 
  } catch (error) {
    throw new Error('Authentication failed');
  }
};

export const getCurrentUser = (token: string): any => {
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || '') as JwtPayload;
    return decoded.user; 
  } catch (e) {
    return null;
  }
};

export const logout = () => {
  localStorage.removeItem('jwtToken');
  window.location.href = '/login';
};

app.listen(3000, () => {
  console.log('Server running on http://localhost:3000');
});
