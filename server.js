const express = require('express');
const authRouter = require('./routes/auth');
const batRouter = require('./routes/bat');
const dotenv = require('dotenv');
const helmet = require('helmet');

const app = express();


dotenv.config();
app.use(helmet());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));
app.use(authRouter);
app.use(batRouter);

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Serveur démarré sur http://localhost:${PORT}`);
});
