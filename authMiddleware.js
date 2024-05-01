

const jwt = require('jsonwebtoken');

function checkAuth(req, res, next) {
    
    const token = req.cookies.token;

    if (!token) {
        return res.status(401).json({ error: 'Unauthorized' });
    }

    try {
        
        const decoded = jwt.verify(token, process.env.SECRET_KEY);

        
        if (Date.now() >= decoded.exp * 1000) {
            
            res.clearCookie('token');
            return res.status(401).json({ error: 'Token expired' });
        }

        
        const currentTime = Math.floor(Date.now() / 1000);
        const lastActivity = decoded.iat; 
        const inactivityPeriod = currentTime - lastActivity;

        if (inactivityPeriod > 120) { 
            
            res.clearCookie('token');
            return res.status(401).json({ error: 'Inactive session' });
        }

        
        const newToken = jwt.sign({ id: decoded.id, username: decoded.username, iat: currentTime }, process.env.SECRET_KEY, { expiresIn: '2m' });
        
        res.cookie('token', newToken, { httpOnly: true });

        
        next();
    } catch (error) {
        
        res.status(401).json({ error: 'Invalid token' });
    }
}

module.exports = { checkAuth };
