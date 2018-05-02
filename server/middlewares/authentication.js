const jwt = require('jsonwebtoken');
const secretKey = process.env.SECRET_KEY;

const Auth = (req, res, next) => {
  const token = req.query.token || req.headers['x-access-token'];
  if (!token) {
    return res.status(401).send({
      success: false,
      message: 'No token provided'
    });
  }

  jwt.verify(token, secretKey, (err, decoded) => {
    if (err) {
      return res.status(401).json({
        success: false,
        messsage: 'Invalid token provided'
      });
    }

    req.roleId = decoded.roleId;
    req.userId = decoded.userId;
    return next();
  });
};

const isAdmin = (req, res, next) => {
  const Admin = 2;
  const SuperAdmin = 3;
  if (req.roleId === Admin && SuperAdmin) {
    return next();
  }
  res.status(403).send('You are not an Authorised user');
};
module.exports = { isAdmin, Auth };
