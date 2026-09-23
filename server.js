const express = require('express');
const authRouter = require('./routes/auth');

const app = express();

app.use(express.json());
app.use(express.static('public'));
app.use('/auth', authRouter);

const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Serveur démarré sur http://localhost:${PORT}`);
});

