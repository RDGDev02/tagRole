const express = require('express');
const axios = require('axios');
const dotenv = require('dotenv');
const expressSession = require('express-session');
const ejs = require('ejs');
const session = require('express-session');
const path = require('path');

dotenv.config();

const clientId = process.env.CLIENT_ID;
const clientSecret = process.env.CLIENT_SECRET;

const redirectURI = process.env.CLIENT_REDIRECT;
const sessionSecret = process.env.SESSION_SECRET;

const app = express();
const port = 3000;




app.use(
  expressSession({
    secret: sessionSecret,
    resave: false,
    saveUninitialized: true,
    cookie: {
      maxAge: 3600000,
    },
  })
);
app.set('views', __dirname + '/views');
app.set('view engine', 'ejs');
app.use(express.static(path.join(__dirname, 'public')));

app.get('/', (req, res) => {
  res.render('index');
});

app.get('/login', (req, res) => {
  const authURL = `https://discord.com/oauth2/authorize?client_id=${clientId}&scope=identify%20guilds%20guilds.members.read&response_type=code&redirect_uri=${encodeURIComponent(redirectURI)}`;

 
  res.redirect(authURL);
});

app.get('/callback', async (req, res) => {
  
  const code = req.query.code;
  const tokenURL = 'https://discord.com/api/oauth2/token';

  const data = {
    client_id: clientId,
    client_secret: clientSecret,
    grant_type: 'authorization_code',
    code,
    redirect_uri: redirectURI,
    scope: 'identify guilds',
  };

  try {
    const response = await axios.post(tokenURL, new URLSearchParams(data), {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
    });

    const { access_token } = response.data;

    const guildsResponse = await axios.get('https://discord.com/api/users/@me/guilds', {
      headers: {
        Authorization: `Bearer ${access_token}`,
      },
    });
   
    // Check if the desired server (guild) ID is present in the list of guilds
    const desiredGuildId = '939607711002296370'; // Replace with the actual guild ID
    const isMemberOfDesiredGuild = guildsResponse.data.some(guild => guild.id === desiredGuildId);
    let inServer = true;
    let uName = "";
    let tagRole = "";
    if (!isMemberOfDesiredGuild) {
        const userInfo = await axios.get('https://discord.com/api/users/@me', {
        headers: {
          Authorization: `Bearer ${access_token}`,
        },
        });
        inServer = false;
        uName = userInfo.data.username;
        console.log(userInfo.data);

    }

    else {

          // Use the access token to fetch user data
          const userResponse = await axios.get('https://discord.com/api/users/@me/guilds/939607711002296370/member', {
            headers: {
              Authorization: `Bearer ${access_token}`,
            },
          });
        
          const roles = userResponse.data.roles;
          
          roles.forEach((role, index) => {
            // Do something with the role, for example, log it to the console
            if(role === "992300210132889750"){
              tagRole = "Alpha";
            }
            else if(role === "949621526003613777"){
              tagRole = "Beta";
              
            }
            else if(role === "949621544794091530"){
              tagRole = "Gamma";
            }
            
          });

          if(tagRole === ""){
            tagRole = "notHolder"
          }
          const { nick } = userResponse.data;
          const { global_name } = userResponse.data.user;
          
          if(nick){
            uName = nick;
          }
          else {
            uName = global_name;
          }
        
          
      }
      req.session.accessToken = access_token;
      req.session.uName = uName;
      req.session.tagRole = tagRole;
      req.session.inServer = inServer;
    res.redirect('/dashboard');
  } catch (error) {
    console.error('Error exchanging code for token:', error);
    res.redirect('/'); // Redirect to the root URL on authentication failure.
  }
});

app.get('/dashboard', (req, res) => {
  if (!req.session.accessToken) {
    res.redirect('/login');
  } else {
    // Use req.session.accessToken to access the user's Discord data
   
    res.render('dashboard', { 
      uName:   req.session.uName,
      tagRole:    req.session.tagRole,
      inServer: req.session.inServer
     });
  }
});

app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});
