const crypto = require('crypto');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { authenticator } = require('@otplib/preset-v11');
const qrcode = require('qrcode');
const db = require('../config/db');

const getCookie = (req, name) => req.headers.cookie
    ?.split(';')
    .map(cookie => cookie.trim())
    .find(cookie => cookie.startsWith(`${name}=`))
    ?.slice(name.length + 1);

exports.login = async (req, res) => {
    const { username, password } = req.body || {};

    try {
        const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(401).json({ error: 'Email ou mot de passe incorrect' });
        }

        if (user.two_factor_enabled === 0 || !user.two_factor_secret) {
            return res.status(403).json({
                error: 'L\'authentification à deux facteurs est requise. Veuillez configurer 2FA avant de vous connecter.',
                requires2FASetup: true,
            });
        }

        if (user.two_factor_enabled === 1) {
            return res.status(200).json({
                message: '2FA requis',
                requires2FA: true,
                username: user.username,
            });
        }

        const token = jwt.sign(
            { id: user.id, username: user.username },
            process.env.SESSION_SECRET,
            { expiresIn: '15m' }
        );
        const refreshToken = crypto.randomBytes(40).toString('hex');
        const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();

        db.prepare('INSERT INTO refresh_tokens (token, user_id, expires_at) VALUES (?, ?, ?)')
            .run(refreshToken, user.id, expiresAt);

        res.cookie('token', token, { httpOnly: true, sameSite: 'strict', maxAge: 15000, path: '/' });
        res.cookie('refreshToken', refreshToken, {
            httpOnly: true,
            sameSite: 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000,
            path: '/',
        });

        return res.json({ message: 'Connexion réussie.' });
    } catch (error) {
        console.error('Erreur lors de la connexion :', error);
        return res.status(500).json({ error: 'Erreur serveur' });
    }
};

exports.logout = (req, res) => {
    const refreshToken = getCookie(req, 'refreshToken');

    try {
        if (refreshToken) {
            db.prepare('DELETE FROM refresh_tokens WHERE token = ?').run(refreshToken);
        }

        res.clearCookie('token', { path: '/' });
        res.clearCookie('refreshToken', { path: '/' });
        return res.json({ message: 'Déconnexion et révocation réussies.' });
    } catch (error) {
        console.error('Erreur lors de la déconnexion :', error);
        return res.status(500).json({ error: 'Erreur serveur lors de la déconnexion' });
    }
};

exports.register = async (req, res) => {
    const { username, password } = req.body || {};

    if (!username || !password) {
        return res.status(400).json('Username et password sont requis');
    }

    if (password.length < 8) {
        return res.status(400).json('Le mot de passe doit contenir au moins 8 caractères');
    }

    const formattedUsername = username.trim();

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const existingUser = db.prepare('SELECT * FROM users WHERE username = ?').get(formattedUsername);

        if (existingUser) {
            return res.status(409).json('Nom d\'utilisateur déjà utilisé');
        }

        db.prepare('INSERT INTO users (username, password) VALUES (?, ?)')
            .run(formattedUsername, hashedPassword);
        return res.status(201).json('Utilisateur enregistré avec succès');
    } catch (error) {
        console.error('Erreur lors de l\'enregistrement de l\'utilisateur :', error);
        return res.status(500).json('Erreur lors de l\'enregistrement de l\'utilisateur');
    }
};

exports.changePassword = async (req, res) => {
    const { currentPassword, newPassword } = req.body || {};

    if (typeof currentPassword !== 'string' || typeof newPassword !== 'string') {
        return res.status(400).json({ error: 'Ancien et nouveau mots de passe requis' });
    }

    const strongPasswordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9\s])[\s\S]{12,}$/;
    if (!strongPasswordRegex.test(newPassword)) {
        return res.status(400).json({
            error: 'Le nouveau mot de passe doit contenir au moins 12 caractères, une majuscule, une minuscule, un chiffre et un caractère spécial',
        });
    }

    try {
        const user = db.prepare('SELECT password FROM users WHERE id = ?').get(req.user.id);
        if (!user) {
            return res.status(404).json({ error: 'Utilisateur introuvable' });
        }

        if (!(await bcrypt.compare(currentPassword, user.password))) {
            return res.status(400).json({ error: 'Ancien mot de passe incorrect' });
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);
        db.prepare('UPDATE users SET password = ? WHERE id = ?').run(hashedPassword, req.user.id);

        return res.json({ message: 'Mot de passe modifié avec succès' });
    } catch (error) {
        console.error('Erreur lors du changement de mot de passe :', error);
        return res.status(500).json({ error: 'Erreur serveur lors du changement de mot de passe' });
    }
};

exports.submitReport = (req, res) => {
    const { content } = req.body;
    const userId = req.session.user.id;

    if (!content) {
        return res.status(400).json('Le contenu du rrouterort est requis');
    }

    try {
        db.prepare('INSERT INTO reports (content, user_id) VALUES (?, ?)').run(content, userId);
        return res.status(201).json('Rrouterort soumis avec succès', '');
    } catch (error) {
        console.error('Erreur lors de la soumission du rrouterort :', error);
        return res.status(500).json('Erreur lors de la soumission du rrouterort');
    }
};

exports.refreshToken = (req, res) => {
    const refreshToken = getCookie(req, 'refreshToken');
    if (!refreshToken) {
        return res.status(401).json({ error: 'Accès refusé' });
    }

    const storedToken = db.prepare('SELECT * FROM refresh_tokens WHERE token = ?').get(refreshToken);
    if (!storedToken || new Date() > new Date(storedToken.expires_at)) {
        return res.status(401).json({ error: 'Session expirée, reconnectez-vous' });
    }

    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(storedToken.user_id);
    const newToken = jwt.sign(
        { id: user.id, username: user.username },
        process.env.SESSION_SECRET,
        { expiresIn: '15m' }
    );

    res.cookie('token', newToken, { httpOnly: true, sameSite: 'strict', maxAge: 900000, path: '/' });
    return res.json({ message: 'Jeton d\'accès rafraîchi.' });
};

exports.setup2FA = async (req, res) => {
    const { username } = req.body;
    const existingUser = db.prepare('SELECT * FROM users WHERE username = ?').get(username);

    if (!existingUser) {
        return res.status(404).json({ error: 'Utilisateur introuvable' });
    }

    if (existingUser.two_factor_enabled === 1) {
        return res.status(400).json({ error: '2FA est déjà activé pour cet utilisateur' });
    }

    const secret = authenticator.generateSecret();
    const otpauth = authenticator.keyuri(username, 'Batcave', secret);

    db.prepare('UPDATE users SET two_factor_secret = ? WHERE username = ?').run(secret, username);

    const qrCodeImage = await qrcode.toDataURL(otpauth);
    return res.json({ qrCode: qrCodeImage, secret });
};

exports.confirm2FA = (req, res) => {
    const { username, code } = req.body;
    const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
    const isValid = authenticator.check(code, user.two_factor_secret);
    if (!isValid) {
        return res.status(401).json({ error: 'Code incorrect. Activation 2FA échouée' });
    }

    db.prepare('UPDATE users SET two_factor_enabled = 1 WHERE username = ?').run(username);
    return res.json({ success: true, message: '2FA activé avec succès' });
};

exports.verify2FA = (req, res) => {
    const { username, code } = req.body;
    const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);

    if (!user) {
        return res.status(404).json({ error: 'Utilisateur introuvable' });
    }

    const isValid = authenticator.check(code, user.two_factor_secret);
    if (!isValid) {
        return res.status(401).json({ error: 'Code 2FA invalide ou expiré' });
    }

    const token = jwt.sign(
        { id: user.id, username: user.username },
        process.env.SESSION_SECRET,
        { expiresIn: '15m' }
    );
    res.cookie('token', token, { httpOnly: true, sameSite: 'strict', maxAge: 15 * 60 * 1000, path: '/' });
    return res.json({
        success: true,
        message: 'Authentification double facteur réussie !',
    });
};
