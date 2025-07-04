// backend/server.js

// -------------------
// SETUP
// -------------------
const express = require('express');
const cors = require('cors');
const { google } = require('googleapis');
const dotenv = require('dotenv');
const fetch = require('node-fetch');

dotenv.config();

const app = express();
const port = process.env.PORT || 5001; // Allow port to be configured via .env

// This is a simple in-memory store for user tokens.
// In a production app, you would use a database (e.g., Redis, PostgreSQL).
const userTokens = {};

// -------------------
// MIDDLEWARE
// -------------------
app.use(cors({ origin: process.env.FRONTEND_URL || 'http://localhost:3000', credentials: true }));
app.use(express.json()); // Allow server to parse JSON request bodies

// -------------------
// GOOGLE OAUTH SETUP
// -------------------
const oauth2Client = new google.auth.OAuth2(
  process.env.GOOGLE_CLIENT_ID,
  process.env.GOOGLE_CLIENT_SECRET,
  process.env.GOOGLE_REDIRECT_URI // This is 'http://localhost:5001/auth/google/callback'
);

// The scopes define the permissions your app is requesting from the user.
const scopes = [
  'https://www.googleapis.com/auth/userinfo.profile',
  'https://www.googleapis.com/auth/userinfo.email',
  'https://www.googleapis.com/auth/cloud-platform', // Required for Vertex AI / Gemini
];

// Listen for token events to save the new token.
oauth2Client.on('tokens', (tokens) => {
  if (tokens.refresh_token) {
    // Store the new refresh token
    console.log('Received new refresh token');
    // Find the user associated with this client and update their tokens.
    // This part requires a reverse lookup from access token to user, which is complex.
    // A better approach is to manage tokens per user more explicitly.
  }
  console.log('Access token refreshed');
});

// -------------------
// ROUTES
// -------------------

/**
 * @route GET /auth/google
 * @description Redirects the user to the Google OAuth consent screen.
 */
app.get('/auth/google', (req, res) => {
  console.log('user click sign in with google')
  const url = oauth2Client.generateAuthUrl({
    access_type: 'offline', // 'offline' gets you a refresh token
    scope: scopes,
    prompt: 'consent', // Ensures the user is prompted for consent, needed to get a refresh token every time.
  });
  res.redirect(url);
});

/**
 * @route GET /auth/google/callback
 * @description The callback URL that Google redirects to after user consent.
 * It exchanges the authorization code for an access token.
 */
app.get('/auth/google/callback', async (req, res) => {
  console.log('user has chosen a Google account')
  try {
    const { code } = req.query;
    if (!code) {
      return res.status(400).send('Authorization code is missing.');
    }

    const { tokens } = await oauth2Client.getToken(code);

    // IMPORTANT: Create a new OAuth2 client for the user to handle tokens independently.
    const userClient = new google.auth.OAuth2();
    userClient.setCredentials(tokens);

    const oauth2 = google.oauth2({ version: 'v2', auth: userClient });
    const { data: userInfo } = await oauth2.userinfo.get();

    // For testing with Postman, log the user ID.
    console.log(`User authenticated successfully. User ID: ${userInfo.id}`);

    // Store the user-specific client. The tokens are attached to it.
    userTokens[userInfo.id] = userClient;
    console.log(`Tokens stored for user: ${userInfo.email}`);

    // SECURITY BEST PRACTICE:
    // In a production app, do NOT pass the user ID in the URL.
    // Instead, create a session (e.g., using express-session) or generate a
    // JWT (JSON Web Token) to send to the frontend. The frontend would then
    // store this securely (e.g., in an HttpOnly cookie) and send it back
    // in the Authorization header for authenticated requests.
    // For this example, we redirect and the frontend will have to ask for the user ID.
    res.redirect(process.env.FRONTEND_URL || 'http://localhost:3000');

  } catch (error) {
    console.error('Error during Google OAuth callback:', error);
    res.status(500).send('Authentication failed.');
  }
});

/**
 * @route POST /api/chat
 * @description Proxies a chat request to the Google Gemini API.
 */
app.post('/api/chat', async (req, res) => {
  const { userId, prompt } = req.body;

  if (!userId || !prompt) {
    return res.status(400).json({ error: 'User ID and prompt are required.' });
  }

  // Retrieve the user-specific OAuth2 client
  const userClient = userTokens[userId];
  if (!userClient) {
    return res.status(401).json({ error: 'User not authenticated or session expired. Please log in again.' });
  }

  try {
    // The library will automatically use the refresh token to get a new access token if needed.
    const accessToken = await userClient.getAccessToken();

    const projectId = process.env.GOOGLE_PROJECT_ID;
    const model = process.env.GEMINI_MODEL || 'gemini-2.5-flash';
    const location = process.env.GEMINI_LOCATION || 'us-central1';

    const apiUrl = `https://us-central1-aiplatform.googleapis.com/v1/projects/${projectId}/locations/${location}/publishers/google/models/${model}:generateContent`;

    const payload = {
      contents: [{
        role: 'user',
        parts: [{ text: prompt }],
      }],
    };

    try {
      const apiResponse = await fetch(apiUrl, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${accessToken.token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(payload),
      });

      if (!apiResponse.ok) {
        const errorBody = await apiResponse.text();
        console.error('Gemini API Error:', errorBody, 'Status:', apiResponse.status);
        return res.status(apiResponse.status).json({ error: `Gemini API request failed: ${errorBody}` });
      }

      const data = await apiResponse.json();

      const botResponse = data.candidates?.[0]?.content?.parts?.[0]?.text || "Sorry, I couldn't get a response.";
      res.json({ response: botResponse });
    } catch (error) {
      console.error('Error calling Gemini API:', error);
      // This could be a token error, network error, etc.
      res.status(500).json({ error: 'Failed to get response from Gemini.' });
    }
  }
  catch (error) {
    console.error('Error calling Gemini API:', error);
      // This could be a token error, network error, etc.
      res.status(500).json({ error: 'Failed to get response from Gemini.' });
  }
});

// -------------------
// SERVER START
// -------------------
app.listen(port, () => {
  console.log(`Backend server running at http://localhost:${port}`);
  console.log('Ensure you have a .env file with GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, GOOGLE_REDIRECT_URI, GOOGLE_PROJECT_ID, and optionally PORT, FRONTEND_URL, GEMINI_MODEL, GEMINI_LOCATION');
});