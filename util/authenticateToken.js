const jwt = require('jsonwebtoken');

// Middleware function to authenticate JWT
const authenticateToken = (req, res, next) => {
    // Normalize header key for case-insensitivity
    const authHeader = req.headers['authorization']; // Use lowercase for consistency
    const token = authHeader && authHeader.split(' ')[1]; // Extract token from "Bearer TOKEN" format

    // If no token is provided, return 401 Unauthorized
    if (token == null) {
        return res.status(401).json({ message: 'Access token is missing' });
    }

    // Verify the token
    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
        // If an error occurs or the token is invalid, return 403 Forbidden
        if (err) {
            return res.status(403).json({ message: 'Invalid access token' });
        }

        // If token is valid, attach the user to the request object
        req.user = user;
        next(); // Proceed to the next middleware or route handler
    });
};

module.exports = authenticateToken;
