const jwt = require('jsonwebtoken');

const isAuthenticated = (req, res, next) => {
    const tokenCookie = req.headers.cookie
        ?.split(';')
        .map(cookie => cookie.trim())
        .find(cookie => cookie.startsWith('token='));

    if (!tokenCookie) {
        return rejectAuthentication(req, res);
    }

    try {
        req.user = jwt.verify(tokenCookie.slice('token='.length), process.env.SESSION_SECRET);
        return next();
    } catch (error) {
        return rejectAuthentication(req, res);
    }
};

function rejectAuthentication(req, res) {
    if (req.path.startsWith('/api/')) {
        return res.status(401).json({ erreur: 'Authentification requise' });
    }

    return res.redirect('/login');
}

module.exports = isAuthenticated;