/**
 * Checks the parameter to see if it is a a String with a length greater than 0.
 *
 * @param {string} param the value to check
 * @returns true if the parameter is a String with a length greater than 0, false otherwise
 */
const isStringProvided = (param) => param !== undefined && param.length > 0;

const isValidPassword = (pwd) => {
    return new RegExp("(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[^A-Za-z0-9])(?=.{8,})").test(pwd);
};

module.exports = {
    isStringProvided,
    isValidPassword,
};
