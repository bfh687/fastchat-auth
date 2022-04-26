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
 * @api {get} /auth Request to login a user
 * @apiName GetAuth
 * @apiGroup Auth
 *
 * @apiHeader {String} authorization "username:password" using basic auth
 *
 * @apiSuccess (201: Success) {boolean} success whether credentials match
 * @apiSuccess (201: Success) {String} message "Authentication Successful!""
 * @apiSuccess (201: Success) {String} token JSON Web Token
 *
 *  * @apiSuccessExample {json} Success-Response:
 *     HTTP/1.1 201 OK
 *     {
 *       "success": true,
 *       "message": "Authentication Successful!",
 *       "token": "eyJhbGciO...abc123"
 *     }
 *
 * @apiError (400: Missing Authorization Header) {String} message "Missing Authorization Header"
 * @apiError (400: Malformed Authorization Header) {String} message "Malformed Authorization Header"
 * @apiError (400: Invalid Credentials) {String} message "Credentials Did Not Match"
 *
 * @apiError (401: User Not Verified) {String} message "Email Not Verified"
 *
 * @apiError (404: User Not Found) {String} message "User Not Found"
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
            res.status(400).json({ message: "Missing Authorization Header" });
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
                message: "Malformed Authorization Header",
            });
        }
    },
    (req, res) => {
        const query = `select memberid, username, email, password, salt, verification from members
                       where email=$1`;
        const values = [req.auth.email];

        pool.query(query, values)
            .then((result) => {
                if (result.rowCount == 0) {
                    res.status(404).send({
                        message: "User Not Found",
                    });
                    return;
                }

                if (result.rows[0].verification == 0) {
                    res.status(401).send({
                        message: "Email Not Verified",
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

                    res.status(201).send({
                        success: true,
                        message: "Authentication Successful",
                        token: token,
                    });
                } else {
                    res.status(400).send({
                        message: "Credentials Did Not Match",
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
