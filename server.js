const express = require('express');
const authRouter = require('./routes/auth');
const batRouter = require('./routes/bat');
const dotenv = require('dotenv');
const session = require('express-session');

const app = express();

dotenv.config();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));
app.use(
  session({
    secret: process.env.SESSION_SECRET || 'batcave-secret',
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: 'strict',
      maxAge: 1800000
    }
  })
);
app.use('/auth', authRouter);
app.use(batRouter);

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Serveur démarré sur http://localhost:${PORT}`);
});
