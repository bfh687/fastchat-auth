const express = require("express");
const router = express.Router();

const pool = require("../utilities").pool;

const validation = require("../utilities").validation;
const isStringProvided = validation.isStringProvided;
const isValidPassword = validation.isValidPassword;
const isValidUsername = validation.isValidUsername;

const generateHash = require("../utilities").generateHash;
const generateSalt = require("../utilities").generateSalt;

const jwt = require("jsonwebtoken");
const sendVerificationEmail = require("../utilities").sendVerificationEmail;

const remove = (memberid) => {
    const query = "delete from members where memberid = $1";
    const values = [memberid];

    // delete user from the database
    pool.query(query, values);
};

/**
 * @api {post} /auth Request to register a user
 * @apiName PostAuth
 * @apiGroup Auth
 *
 * @apiParam {String} first a user's first name
 * @apiParam {String} last a user's last name
 * @apiParam {String} email a user's unique email
 * @apiParam {String} password a user's password
 * @apiParam {String} [username] a unique username, if none provided, email will be used
 *
 * @apiParamExample {json} Request-Body-Example:
 *  {
 *      "first":"Fast",
 *      "last":"Chat",
 *      "email":"fastchat@mail.com",
 *      "password":"FastChatPass1!"
 *  }
 *
 * @apiSuccess (201: Success) {boolean} success whether the user is registered
 * @apiSuccess (201: Success) {String} message "User Registered Successfully!""
 * @apiSuccess (201: Success) {String} email the email of the user
 *
 *  * @apiSuccessExample {json} Success-Response:
 *     HTTP/1.1 201 OK
 *     {
 *       "success": true,
 *       "message": "User Registered Successfully!",
 *       "email": "fastchat@mail.com"
 *     }
 *
 * @apiError (400: Missing Parameters) {String} message "Missing Required Information"
 *
 * @apiError (400: Username Already Exists) {String} message "Username Already Exists"
 * @apiError (400: Email Already Exists) {String} message "Email Already Exists"
 *
 * @apiError (400: Invalid Email) {String} message "Invalid Email"
 *
 * @apiError (400: Username Does Not Meet Requirements) {String} message "Username Does Not Meet Minimum Requirements"
 * @apiError (400: Password Does Not Meet Requirements) {String} message "Password Does Not Meet Minimum Requirements"
 *
 * @apiError (400: Other Error) {String} message "Other Error, See Detail"
 * @apiError (400: Other Error) {String} detail information about the error
 *
 */
router.post("/", (req, res) => {
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
        // check if password meets minimum strength requirements
        if (!isValidPassword(password)) {
            res.status(400).send({
                message: "Password Does Not Meet Minimum Requirements",
            });
            return;
        }

        // check if password meets minimum length requirement
        if (!isValidUsername(username)) {
            res.status(400).send({
                message: "Username Does Not Meet Minimum Requirements",
            });
            return;
        }

        const salt = generateSalt(32);
        const salted_hash = generateHash(req.body.password, salt);

        const query =
            "insert into members(firstname, lastname, username, email, password, salt) VALUES ($1, $2, $3, $4, $5, $6) returning memberid, email, firstname";
        const values = [first, last, username, email, salted_hash, salt];

        pool.query(query, values)
            .then((result) => {
                const token = jwt.sign(
                    {
                        memberid: result.rows[0].memberid,
                        name: result.rows[0].firstname,
                        email: result.rows[0].email,
                    },
                    process.env.JSON_WEB_TOKEN,
                    {
                        expiresIn: "10m",
                    }
                );

                sendVerificationEmail(req.body.email, token, (err) => {
                    if (err) {
                        res.status(400).send({
                            message: "Invalid Email",
                        });
                        remove(result.rows[0].memberid);
                        return;
                    } else {
                        res.status(201).send({
                            success: true,
                            message: "User Registered Successfully!",
                            email: req.body.email,
                        });
                    }
                });
            })
            .catch((error) => {
                console.log(error);
                if (error.constraint == "members_username_key") {
                    res.status(400).send({
                        message: "Username Already Exists",
                    });
                } else if (error.constraint == "members_email_key") {
                    res.status(400).send({
                        message: "Email Already Exists",
                    });
                } else {
                    console.log(error);
                    res.status(400).send({
                        message: "Other Error, See Detail",
                        detail: error.detail,
                    });
                }
            });
    } else {
        res.status(400).send({
            message: "Missing Required Information",
        });
    }
});

module.exports = router;
