const express = require("express");
const router = express.Router();

const jwt = require("jsonwebtoken");
const pool = require("../utilities").pool;

const success_title = "Email Successfully Verified!";
const verified_title = "Email Already Verified!";
const expired_title = "Email Verification Link Expired!";
const error_title = "Error Verifying Your Account!";

const success_message =
    "\n\nThank you for verifying your FastChat account! Please continue to the app and login to your new account.";
const verified_message =
    "\n\nLooks like this email is already registered and ready for use with FastChat! Please continue to the app to login to your account.";
const expired_message =
    "\n\nThis verification link has expired. If you would like to continue with the registration process, please re-register through the FastChat app.";
const error_message =
    "\n\nThere was an error verifying your account. Please try re-registering through the FastChat app.";

const remove = (memberid) => {
    const query = "delete from members where memberid = $1";
    const values = [memberid];

    // delete user from the database
    pool.query(query, values);
};

/**
 * @api {get} /auth/verify Request to verify a user
 * @apiName VerifyAuth
 * @apiGroup Auth
 *
 * @apiParam {String} token a signed jwt token
 *
 * @apiSuccess (Success 200) {boolean} success true when the user is verified
 * @apiSuccess (Success 200) {String} email the email of the verified user
 *
 * @apiError (400: Error Validating Email) {String} message "Error validating the email address"
 * @apiError (403: Invalid Token) {String} message "Invalid JWT token"
 */
router.get(
    "/:token",
    (req, res, next) => {
        const token = req.params.token;

        jwt.verify(
            token,
            process.env.JSON_WEB_TOKEN,
            { ignoreExpiration: true },
            (err, decoded) => {
                // most likely JWT is expired
                const curr_time = new Date().getTime() / 1000;
                if (err || decoded.exp < curr_time) {
                    // check if user is already verified.
                    const query = "select * from members where memberid = $1 and verification = 1";
                    const values = [decoded.memberid];

                    pool.query(query, values)
                        .then((result) => {
                            // user is unverified, remove user from database
                            if (result.rowCount == 0) {
                                remove(decoded.memberid);

                                res.status(403).render("email-confirmation", {
                                    name: decoded.name,
                                    title: expired_title,
                                    message: expired_message,
                                });
                            }
                            // user is already verified
                            else {
                                res.status(400).render("email-confirmation", {
                                    name: decoded.name,
                                    title: verified_title,
                                    message: verified_message,
                                });
                            }
                        })
                        .catch((err) => {
                            // remove user from database
                            remove(req.decoded.memberid);

                            res.status(400).render("email-confirmation", {
                                name: req.decoded.name,
                                title: error_title,
                                message: error_message,
                            });
                        });
                } else {
                    req.decoded = decoded;
                    next();
                }
            }
        );
    },
    (req, res) => {
        const query = "update members set verification = 1 where memberid = $1";
        const values = [req.decoded.memberid];

        pool.query(query, values)
            .then((result) => {
                res.status(200).render("email-confirmation", {
                    name: req.decoded.name,
                    title: success_title,
                    message: success_message,
                });
            })
            .catch((err) => {
                // remove user from database
                remove(req.decoded.memberid);

                res.status(400).render("email-confirmation", {
                    name: req.decoded.name,
                    title: error_title,
                    message: error_message,
                });
            });
    }
);

module.exports = router;
