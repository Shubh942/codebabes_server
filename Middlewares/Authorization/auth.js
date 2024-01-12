const CustomError = require("../../Helpers/error/CustomError");
const User = require("../../Models/user");
const jwt = require("jsonwebtoken");
const asyncErrorWrapper = require("express-async-handler");
const {
  isTokenIncluded,
  getAccessTokenFromHeader,
} = require("../../Helpers/auth/tokenHelpers");

const getAccessToRoute = asyncErrorWrapper(async (req, res, next) => {
  const { JWT_SECRET_KEY } = process.env;

  if (!isTokenIncluded(req)) {
    return next(
      new CustomError("You are not authorized to access this route ", 401)
    );
  }

  const accessToken = getAccessTokenFromHeader(req);

  const decoded = jwt.verify(accessToken, JWT_SECRET_KEY);

  const user = await User.findById(decoded.id);

  if (!user) {
    return next(
      new CustomError("You are not authorized to access this route ", 401)
    );
  }
  //   console.log(user);

  req.user = user;

  next();
});

const restrictTo = asyncErrorWrapper(async (req, res, next) => {
  //   console.log(req.user);
  if (req.user.role !== "admin") {
    return next(
      new CustomError("You do not permission to perform this action", 403)
    );
  }
  next();
});

module.exports = { getAccessToRoute, restrictTo };
