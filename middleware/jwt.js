const jwt = require("jsonwebtoken");
const config = {
    secret: process.env.JSON_WEB_TOKEN,
};

const checkToken = (req, res, next) => {
    let token = req.headers["x-access-token"] || req.headers["authorization"];

    if (token) {
        if (token.startsWith("Bearer ")) {
            // Remove Bearer from string
            token = token.slice(7, token.length);
        }

        jwt.verify(token, config.secret, (err, decoded) => {
            if (err) {
                return res.status(403).json({
                    success: false,
                    message: "token is not valid",
                });
            } else {
                req.decoded = decoded;
                next();
            }
        });
    } else {
        return res.status(401).json({
            success: false,
            message: "auth token is not supplied",
        });
    }
};

module.exports = {
    checkToken: checkToken,
};
