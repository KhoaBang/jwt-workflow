const jwt = require('jsonwebtoken');

// middleware để validate jwt
const authenticateToken = (req, res, next) => {

    const authHeader = req.headers['authorization']; 
    const token = authHeader && authHeader.split(' ')[1]; 

    if (token == null) {
        return res.status(401).json({ message: 'Access token is missing' });
    }

    // Verify the token
    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ message: 'Invalid access token' });
        }

        req.user = user;
        next(); 
    });
};

module.exports = authenticateToken;
