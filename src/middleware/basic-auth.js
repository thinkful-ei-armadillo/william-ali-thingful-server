'use strict';

// middleware that can connect to multiple endpoints
function requireAuth(req, res, next) {
//   console.log('requireAuth');
//   console.log(req.get('Authorization'));
  const authToken = req.get('Authorization') || '';

  let bearerToken;
  // conditional to check if bearer token is present. If not, throw 401
  if (!authToken.toLowerCase().startsWith('bearer ')) {
    return res.status(401).json({
      error: 'Missing bearer token'
    });
  } else {
    // if bearerToken is present, slice away bearer and store actual token in bearerToken variable
    bearerToken = authToken.slice(6, authToken.length);
  }

  // parse the base64 bearer token value out of header
  const [tokenUserName, tokenPassword] = Buffer
    .from(bearerToken, 'base64')
    .toString()
    .split(':');
  // throw error if user or pw arent there
  if (!tokenUserName || !tokenPassword) {
    return res.status(401).json({ 
      error: 'Unauthorized request'});
  }

  // query blogful_users db to check for user matching this username
  req.app.get('db')('blogful_users')
    .where({ user_name: tokenUserName })
    .first()
    .then(user => {
      // if no matching user OR password, throw 401 unauthorized
      if (!user || user.password !== tokenPassword) {
        return res.status(401).json({ 
          error: 'Unauthorized request'});
      }
      next();
    })
    .catch(next);
}
  
module.exports = {
  requireAuth,
};