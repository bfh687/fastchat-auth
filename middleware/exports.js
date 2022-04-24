const checkToken = require("./jwt.js").checkToken;
const jsonErrorInBody = require("./errors.js").jsonErrorInBody;

module.exports = {
    checkToken,
    jsonErrorInBody,
};
