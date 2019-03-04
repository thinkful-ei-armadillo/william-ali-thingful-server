'use strict';

const AuthService = require('../auth/auth-service');

// middleware that can connect to multiple endpoints
function requireAuth(req, res, next) {
  const authToken = req.get('Authorization') || '';

  let bearerToken;
  // conditional to check if bearer token is present. If not, throw 401
  if (!authToken.toLowerCase().startsWith('bearer ')) {
    return res.status(401).json({
      error: 'Missing bearer token'
    });
  } else {
    // if bearerToken is present, slice away bearer and store actual token in bearerToken variable
    bearerToken = authToken.slice(7, authToken.length);
    console.log(bearerToken);
  }

  // parse the base64 bearer token value out of header
  const [tokenUserName, tokenPassword] = AuthService.parseBasicToken(
    bearerToken
  );

  // throw error if user or pw arent there
  if (!tokenUserName || !tokenPassword) {
    return res.status(401).json({
      error: 'Unauthorized request'
    });
  }

  AuthService.getUserWithUsername(req.app.get('db'), tokenUserName)
    .then(user => {
      if (!user || user.password !== tokenPassword) {
        return res.status(401).json({
          error: 'Unauthorized request'
        });
      }
      req.user = user;
      next();
    })
    .catch(next);
}

module.exports = {
  requireAuth,
};