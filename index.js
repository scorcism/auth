"use strict"
const jwt = require("jsonwebtoken");

class Auth {
  JWT_TOKEN;

  setToken(token) {
    this.JWT_TOKEN = token;
  }

  authenticate(req, res, next) {
    const tokenHeader = req.headers.authorization;

    if (!tokenHeader) {
      return res.status(401).json({
        error: "Unauthorized",
      });
    }

    try {
      const token = tokenHeader.split(" ")[1];

      const user = jwt.verify(token, this.JWT_TOKEN);
      // Authentication successful, attach the user to the request
      req.user = user;

      next();
    } catch (error) {
      return res.status(401).json({
        error: "Unauthorized",
      });
    }
  }

  allow(requireRoles) {
    return (req, res, next) => {
      const user = req.user;
      const userRole = user.role;

      if (userRole && requireRoles.length) {
        if (!this.checkRole(requireRoles, userRole)) {
          // User doesn't have required rights
          return res.status(403).json({ error: "Forbidden" });
        }
      } else {
        // User role or required roles not provided
        return res.status(400).json({ error: "Bad Request" });
      }
      // User has required rights
      next();
    };
  }

  checkRole(requiredRights, userRole) {
    return requiredRights.includes(userRole);
  }
}

module.exports = Auth;
