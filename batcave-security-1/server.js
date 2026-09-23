const express = require('express');
const bcrypt = require('bcrypt');
const db = require('./db');

const app = express();
app.use(express.json());

app.use(express.static('public'));

const PORT = 3000
app.listen(PORT, () => {
    console.log(`Serveur démarré sur http://localhost:${PORT}`)
})

app.post('/register', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json('Username et password sont requis');
    }

    if (password.length < 8) {
        return res.status(400).json('Le mot de passe doit contenir au moins 8 caractères');
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const formattedUsername = username.trim();

    const existingUser = db.prepare('SELECT * FROM users WHERE username = ?').get(formattedUsername);

    if (existingUser) {
        return res.status(409).json('Nom d\'utilisateur déjà utilisé');
    }

    try {
        db.prepare('INSERT INTO users (username, password) VALUES (?, ?)').run(formattedUsername, hashedPassword);
        res.status(201).json('Utilisateur enregistré avec succès');
    } catch (err) {
        res.status(500).json('Erreur lors de l\'enregistrement de l\'utilisateur');
    }
});

const checkAuth = async (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Basic ')) {
        res.setHeader('WWW-Authenticate', 'Basic realm="Administration"')
        return res.status(401).send('Authentification requise')
    }

    const [username, password] = Buffer.from(authHeader.split(' ')[1], 'base64').toString().split(':');

    const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
    if (!user) {
        return res.status(401).json('Utilisateur non trouvé');
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
        return res.status(401).json('Mot de passe incorrect');
    }

    req.user = user;
    next();
};


app.get('/bat-computer', checkAuth, (req, res) => {
    res.sendFile(__dirname + '/private/bat-computer.html');
});

app.get('/api/secrets', checkAuth, (req, res) => {
    const gadgets = [
        { name: 'Batarang', desc: 'Un boomerang en forme de chauve-souris utilisé par Batman.', icon: 'fa-shuriken' },
        { name: 'Batmobile', desc: 'La voiture emblématique de Batman, équipée de gadgets et d\'armes.', icon: 'fa-car' },
        { name: 'Cape de Batman', desc: 'Une cape spéciale qui permet à Batman de planer et de se camoufler.', icon: 'fa-flag' },
        { name: 'Bat-Signal', desc: 'Un projecteur utilisé pour appeler Batman en cas d\'urgence.', icon: 'fa-lightbulb' },
    ];

    res.json({ gadgets });
});

app.get('/api/me', checkAuth, (req, res) => {
    const user = req.user;
    res.json({ username: user.username, id: user.id });
});

app.post('/api/reports', checkAuth, (req, res) => {
    const { content } = req.body;
    const userId = req.user.id;

    if (!content) {
        return res.status(400).json('Le contenu du rapport est requis');
    }

    try {
        db.prepare('INSERT INTO reports (content, user_id) VALUES (?, ?)').run(content, userId);
        res.status(201).json('Rapport soumis avec succès');
    } catch (err) {
        res.status(500).json('Erreur lors de la soumission du rapport');
    }
});
