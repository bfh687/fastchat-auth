const express = require("express");
const router = express.Router();

const pool = require("../utilities").pool;

const validation = require("../utilities").validation;
const isStringProvided = validation.isStringProvided;

const generateHash = require("../utilities").generateHash;

// import jwt tools and jwt itself
const jwt = require("jsonwebtoken");
const config = {
    secret: process.env.JSON_WEB_TOKEN,
};

/**
 * @api {get} /auth Request to sign a user in the system
 * @apiName GetAuth
 * @apiGroup Auth
 *
 * @apiHeader {String} authorization "username:password" uses Basic Auth
 *
 * @apiSuccess {boolean} success true when the name is found and password matches
 * @apiSuccess {String} message "Authentication successful!""
 * @apiSuccess {String} token JSON Web Token
 *
 *  * @apiSuccessExample {json} Success-Response:
 *     HTTP/1.1 201 OK
 *     {
 *       "success": true,
 *       "message": "Authentication successful!",
 *       "token": "eyJhbGciO...abc123"
 *     }
 *
 * @apiError (400: Missing Authorization Header) {String} message "Missing Authorization Header"
 * @apiError (400: Malformed Authorization Header) {String} message "Malformed Authorization Header"
 * @apiError (404: User Not Found) {String} message "User not found"
 * @apiError (400: Invalid Credentials) {String} message "Credentials did not match"
 * @apiError (401: User Not Verified) {String} message "User's email is not verified"
 */
router.get(
    "/",
    (req, res, next) => {
        if (
            isStringProvided(req.headers.authorization) &&
            req.headers.authorization.startsWith("Basic ")
        ) {
            next();
        } else {
            res.status(400).json({ message: "missing authorization header" });
        }
    },
    (req, res, next) => {
        // obtain auth credentials from HTTP Header
        const base64Credentials = req.headers.authorization.split(" ")[1];
        const credentials = Buffer.from(base64Credentials, "base64").toString("ascii");

        // capture credentials
        const [email, password] = credentials.split(":");

        // check that credentials are not empty
        if (isStringProvided(email) && isStringProvided(password)) {
            req.auth = {
                email: email,
                password: password,
            };
            next();
        } else {
            res.status(400).send({
                message: "malformed authorization header",
            });
        }
    },
    (req, res) => {
        const query = `select username, email, password, salt, verification from members
                       where email=$1`;
        const values = [req.auth.email];

        pool.query(query, values)
            .then((result) => {
                if (result.rowCount == 0) {
                    res.status(404).send({
                        message: "user not found",
                    });
                    return;
                }

                if (result.rows[0].verification == 0) {
                    res.status(401).send({
                        message: "email not verified",
                    });
                    return;
                }

                // get salt, hashed password, and compute expected hashed password
                const salt = result.rows[0].salt;
                const salted_hash = result.rows[0].password;
                const expected_hash = generateHash(req.auth.password, salt);

                // compare hashed passwords
                if (salted_hash === expected_hash) {
                    let token = jwt.sign(
                        {
                            memberid: result.rows[0].memberid,
                            username: result.rows[0].username,
                            email: req.auth.email,
                        },
                        config.secret,
                        {
                            expiresIn: "14 days",
                        }
                    );

                    res.json({
                        success: true,
                        message: "authentication successful",
                        token: token,
                    });
                } else {
                    res.status(400).send({
                        message: "credentials did not match",
                    });
                }
            })
            .catch((err) => {
                console.log(err);
                console.log(err.stack);
                res.status(400).send({
                    message: err.detail,
                });
            });
    }
);

module.exports = router;
