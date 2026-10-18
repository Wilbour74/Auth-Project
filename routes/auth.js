const express = require('express');
const path = require('path');
const bcrypt = require('bcrypt');
const db = require('../config/db');
const isAuthenticated = require('../middlewares/authCheck');
const router = express.Router();
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');
const crypto = require('crypto');

dotenv.config();


router.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, '../views', 'login.html'));
});

router.post('/login', async (req, res) => {
    const { username, password } = req.body || {};
    try {
        const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(401).json({ erreur: 'Email ou mot de passe incorrect' })
        }

        const token = jwt.sign(
            { id: user.id, username: user.username },
            process.env.SESSION_SECRET,
            { expiresIn: '15s' }
        );

        const refreshToken = crypto.randomBytes(40).toString('hex');
        const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();

        db.prepare('INSERT INTO refresh_tokens (token, user_id, expires_at) VALUES (?, ?, ?)')
            .run(refreshToken, user.id, expiresAt);

        res.cookie('token', token, { httpOnly: true, sameSite: 'strict', maxAge: 15000, path: '/' });
        res.cookie('refreshToken', refreshToken, { httpOnly: true, sameSite: 'strict', maxAge: 7 * 24 * 60 * 60 * 1000, path: '/' });

        res.json({ message: 'Connexion réussie.' });
    } catch (error) {
        res.status(500).json({ erreur: 'Erreur serveur' });
    }
});

router.post('/logout', (req, res) => {
    const refreshToken = req.headers.cookie
        ?.split(';')
        .map(cookie => cookie.trim())
        .find(cookie => cookie.startsWith('refreshToken='))
        ?.slice('refreshToken='.length);

    try {
        if (refreshToken) {
            db.prepare('DELETE FROM refresh_tokens WHERE token = ?').run(refreshToken);
        }

        res.clearCookie('token', { path: '/' });
        res.clearCookie('refreshToken', { path: '/' });
        return res.json({ message: 'Déconnexion et révocation réussies.' });
    } catch (error) {
        console.error('Erreur lors de la déconnexion :', error);
        return res.status(500).json({ erreur: 'Erreur serveur lors de la déconnexion' });
    }
});

router.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, '../views', 'register.html'));
});

router.get('/change-password', (req, res) => {
    res.sendFile(path.join(__dirname, '../views', 'change-password.html'));
});

router.post('/register', async (req, res) => {
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



router.get('/api/secrets', isAuthenticated, (req, res) => {
    const gadgets = [
        { name: 'Batarang', desc: 'Un boomerang en forme de chauve-souris utilisé par Batman.', icon: 'fa-shuriken' },
        { name: 'Batmobile', desc: 'La voiture emblématique de Batman, équipée de gadgets et d\'armes.', icon: 'fa-car' },
        { name: 'Cape de Batman', desc: 'Une cape spéciale qui permet à Batman de planer et de se camoufler.', icon: 'fa-flag' },
        { name: 'Bat-Signal', desc: 'Un projecteur utilisé pour routereler Batman en cas d\'urgence.', icon: 'fa-lightbulb' },
    ];

    res.json({ gadgets });
});

router.get('/api/me', isAuthenticated, (req, res) => {
    return res.json({ username: req.user.username, id: req.user.id });
});

router.post('/api/auth/change-password', isAuthenticated, async (req, res) => {
    const { currentPassword, newPassword } = req.body || {};

    if (typeof currentPassword !== 'string' || typeof newPassword !== 'string') {
        return res.status(400).json({ erreur: 'Ancien et nouveau mots de passe requis' });
    }

    const strongPasswordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9\s])[\s\S]{12,}$/;
    if (!strongPasswordRegex.test(newPassword)) {
        return res.status(400).json({
            erreur: 'Le nouveau mot de passe doit contenir au moins 12 caractères, une majuscule, une minuscule, un chiffre et un caractère spécial'
        });
    }

    try {
        const user = db.prepare('SELECT password FROM users WHERE id = ?').get(req.user.id);
        if (!user) {
            return res.status(404).json({ erreur: 'Utilisateur introuvable' });
        }

        if (!(await bcrypt.compare(currentPassword, user.password))) {
            return res.status(400).json({ erreur: 'Ancien mot de passe incorrect' });
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);
        db.prepare('UPDATE users SET password = ? WHERE id = ?').run(hashedPassword, req.user.id);

        return res.json({ message: 'Mot de passe modifié avec succès' });
    } catch (error) {
        return res.status(500).json({ erreur: 'Erreur serveur lors du changement de mot de passe' });
    }
});

router.post('/api/reports', (req, res) => {
    const { content } = req.body;
    const userId = req.session.user.id;

    if (!content) {
        return res.status(400).json('Le contenu du rrouterort est requis');
    }

    try {
        db.prepare('INSERT INTO reports (content, user_id) VALUES (?, ?)').run(content, userId);
        res.status(201).json('Rrouterort soumis avec succès', '');
    } catch (err) {
        res.status(500).json('Erreur lors de la soumission du rrouterort');
    }
});

router.post('/api/auth/refresh', (req, res) => {
    const refreshToken = req.headers.cookie
        ?.split(';')
        .map(cookie => cookie.trim())
        .find(cookie => cookie.startsWith('refreshToken='))
        ?.slice('refreshToken='.length);
    if (!refreshToken) return res.status(401).json({ erreur: 'Accès refusé' });

    const storedToken = db.prepare('SELECT * FROM refresh_tokens WHERE token = ?').get(refreshToken);

    if (!storedToken || new Date() > new Date(storedToken?.expires_at)) {
        return res.status(401).json({ erreur: 'Session expirée, reconnectez-vous' });
    }

    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(storedToken.user_id);
    const newToken = jwt.sign(
        { id: user.id, username: user.username },
        process.env.SESSION_SECRET,
        { expiresIn: '15s' }
    );

    res.cookie('token', newToken, { httpOnly: true, sameSite: 'strict', maxAge: 15000, path: '/' });
    res.json({ message: 'Jeton d\'accès rafraîchi.' });
})

module.exports = router;