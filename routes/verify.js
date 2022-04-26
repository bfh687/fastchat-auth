const express = require("express");
const router = express.Router();

const jwt = require("jsonwebtoken");
const pool = require("../utilities").pool;

const remove = (memberid) => {
    const query = "delete from members where memberid = $1";
    const values = [memberid];

    // delete user from the database
    pool.query(query, values);
};

/**
 * @api {get} /auth/verify/:id Request to verify a user
 * @apiName VerifyAuth
 * @apiGroup Auth
 *
 * @apiParam {String} id a signed JWT
 *
 * @apiSuccess (200: Success) {boolean} success whether credentials match
 * @apiSuccess (200: Success) {String} message "Successfully Verified Email!!"
 * @apiSuccess (200: Success) {String} token the verified email
 *
 *  * @apiSuccessExample {json} Success-Response:
 *     HTTP/1.1 200 OK
 *     {
 *       "success": true,
 *       "message": "Successfully Verified Email!",
 *       "token": "fastchat@mail.com"
 *     }
 *
 * @apiError (400: Error Verifying Email) {String} message "Error Verifying Email"
 * @apiError (400: Email Already Verified) {String} message "Email Already Verified"
 *
 * @apiError (403: Expired JWT) {String} message "JWT Expired"
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

                                res.status(403).send({
                                    message: "JWT Expired",
                                });
                            }
                            // user is already verified
                            else {
                                res.status(400).send({
                                    message: "Email Already Verified",
                                });
                            }
                        })
                        .catch((err) => {
                            // remove user from database
                            remove(req.decoded.memberid);

                            res.status(400).send({
                                message: "Error Verifying Email",
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
                res.status(200).send({
                    message: "Successfully Verified Email!",
                });
            })
            .catch((err) => {
                // remove user from database
                remove(req.decoded.memberid);

                res.status(400).send({
                    message: "Error Verifying Email",
                });
            });
    }
);

module.exports = router;
