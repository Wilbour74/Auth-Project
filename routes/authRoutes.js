const express = require('express');
const path = require('path');
const isAuthenticated = require('../middlewares/authCheck');
const authController = require('../controllers/authController');

const router = express.Router();

router.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, '../views', 'login.html'));
});
router.post('/login', authController.login);
router.post('/logout', authController.logout);
router.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, '../views', 'register.html'));
});
router.get('/change-password', (req, res) => {
    res.sendFile(path.join(__dirname, '../views', 'change-password.html'));
});
router.post('/register', authController.register);
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
    res.json({ username: req.user.username, id: req.user.id });
});

router.post('/api/auth/change-password', isAuthenticated, authController.changePassword);
router.post('/api/reports', authController.submitReport);
router.post('/api/auth/refresh', authController.refreshToken);
router.post('/setup-2fa', authController.setup2FA);
router.post('/confirm-2fa', authController.confirm2FA);
router.post('/verify-2fa', authController.verify2FA);

module.exports = router;
