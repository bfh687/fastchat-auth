const express = require("express");
const router = express.Router();

const pool = require("../utilities").pool;

const validation = require("../utilities").validation;
let isStringProvided = validation.isStringProvided;

const generateHash = require("../utilities").generateHash;
const generateSalt = require("../utilities").generateSalt;

const jwt = require("jsonwebtoken");
const sendVerificationEmail = require("../utilities").sendVerificationEmail;

/**
 * @api {post} /auth Request to register a user
 * @apiName PostAuth
 * @apiGroup Auth
 *
 * @apiParam {String} first a user's first name
 * @apiParam {String} last a user's last name
 * @apiParam {String} email a user's email *unique
 * @apiParam {String} password a user's password
 * @apiParam {String} [username] a username *unique, if none provided, email will be used
 *
 * @apiParamExample {json} Request-Body-Example:
 *  {
 *      "first":"Fast",
 *      "last":"Chat",
 *      "email":"fastchat@mail.com",
 *      "password":"fastchatpass"
 *  }
 *
 * @apiSuccess (Success 201) {boolean} success true when the name is inserted
 * @apiSuccess (Success 201) {String} email the email of the user inserted
 *
 * @apiError (400: Missing Parameters) {String} message "Missing required information"
 *
 * @apiError (400: Username exists) {String} message "Username exists"
 * @apiError (400: Email exists) {String} message "Email exists"
 *
 * @apiError (400: Other Error) {String} message "other error, see detail"
 * @apiError (400: Other Error) {String} detail Information about the error
 *
 */
router.post("/", (req, res, next) => {
    const first = req.body.first;
    const last = req.body.last;
    const username = isStringProvided(req.body.username) ? req.body.username : req.body.email;
    const email = req.body.email;
    const password = req.body.password;

    if (
        isStringProvided(first) &&
        isStringProvided(last) &&
        isStringProvided(username) &&
        isStringProvided(email) &&
        isStringProvided(password)
    ) {
        let salt = generateSalt(32);
        let salted_hash = generateHash(req.body.password, salt);

        let query =
            "insert into members(firstname, lastname, username, email, password, salt) VALUES ($1, $2, $3, $4, $5, $6) returning memberid, email";
        let values = [first, last, username, email, salted_hash, salt];

        pool.query(query, values)
            .then((result) => {
                res.status(201).send({
                    success: true,
                    email: req.body.email,
                });

                const token = jwt.sign(
                    {
                        memberid: result.rows[0].memberid,
                        email: result.rows[0].email,
                    },
                    process.env.JSON_WEB_TOKEN,
                    {
                        expiresIn: "1h",
                    }
                );

                sendVerificationEmail(req.body.email, token);
            })
            .catch((error) => {
                if (error.constraint == "members_username_key") {
                    res.status(400).send({
                        message: "username already exists",
                    });
                } else if (error.constraint == "members_email_key") {
                    res.status(400).send({
                        message: "email already exists",
                    });
                } else {
                    res.status(400).send({
                        message: "other error, see detail",
                        detail: error.detail,
                    });
                }
            });
    } else {
        res.status(400).send({
            message: "missing required information",
        });
    }
});

module.exports = router;
