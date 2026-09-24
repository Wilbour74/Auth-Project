const express = require('express');
const path = require('path');
const bcrypt = require('bcrypt');
const db = require('../config/db');
const isAuthenticated = require('../middlewares/authCheck');
const router = express.Router();

router.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, '../views', 'login.html'));
});

router.post('/login', async (req, res, next) => {
    const { username, password } = req.body || {};
    const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
    if (!user || !(await bcrypt.compare(password, user.password))) {
        return res.status(401).json({ erreur: 'Email ou mot de passe incorrect' })
    }
    req.session.regenerate((err) => {
        if (err) {
            return next(err);
        }

        req.session.user = { username: user.username, id: user.id };
        req.session.save(function (err) {
            if (err) return next(err);
            return res.json({
                success: true,
                redirect: '/bat-computer'
            });
        })
    });
});

router.post('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            return res.status(500).json({ erreur: 'Impossible de vous déconnecter' });
        }

        res.clearCookie('connect.sid');
        return res.status(200).json({ success: true, redirect: '/auth/login' });
    });
});

router.get('/register', (req, res) => {
    res.sendFile(path.join(__dirname, '../views', 'register.html'));
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
    const totalUsers = db.prepare('SELECT COUNT(*) AS total FROM users').get().total;

    if (existingUser) {
        return res.status(409).json('Nom d\'utilisateur déjà utilisé');
    }

    try {
        const result = db.prepare('INSERT INTO users (username, password) VALUES (?, ?)').run(formattedUsername, hashedPassword);
        const userId = Number(result.lastInsertRowid);
        req.session.user = { username: formattedUsername, id: userId };
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
    const user = req.session.user;
    if (!user) {
        return res.status(401).json({ erreur: 'Authentification requise' });
    }

    return res.json({ username: user.username, id: user.id });
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

module.exports = router;