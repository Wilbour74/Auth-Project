const express = require('express');
const authRouter = require('./routes/auth');
const dotenv = require('dotenv');
const app = express();
const session = require('express-session');

dotenv.config();

app.use(express.json());
app.use(express.static('public'));
app.use('/auth', authRouter);


const PORT = process.env.PORT || 3000;


app.use(
    session({
        secret: process.env.SESSION_SECRET,
        resave: false,
        saveUninitialized: false,
        cookie: {
            httpOnly: true,
            sameSite: 'strict',
            maxAge: 1800000
        }
    })
)

app.listen(PORT, () => {
  console.log(`Serveur démarré sur http://localhost:${PORT}`)
});
