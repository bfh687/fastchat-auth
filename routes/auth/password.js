const express = require("express");
const router = express.Router();

const pool = require("../../utilities").pool;

const validation = require("../../utilities").validation;
const isStringProvided = validation.isStringProvided;
const isValidPassword = validation.isValidPassword;

const generateHash = require("../../utilities").generateHash;
const generateSalt = require("../../utilities").generateSalt;

/**
 * @api {put} /auth/password Request to change password
 * @apiName PutAuth
 * @apiGroup Auth
 *
 * @apiHeader {String} authorization JWT provided from /auth get
 *
 * @apiParam {String} password the user's new password
 *
 * @apiSuccess (200: Success) {boolean} success whether the password was changed
 * @apiSuccess (200: Success) {String} message "Password Successfully Changed!"
 *
 * @apiError (400: Password Does Not Meet Requirements) {String} message "Password Does Not Meet Minimum Requirements"
 * @apiError (400: Old Password Does Not Match) {String} message "Old Password Does Not Match"
 * @apiError (400: Error Changing Password) {String} message "Error Changing Password"
 * @apiError (400: Missing Parameters) {String} message "Missing Required Information"
 *
 */
router.post("/", (req, res) => {
  const old_password = req.body.old_password;
  const new_password = req.body.new_password;

  if (isStringProvided(old_password && new_password)) {
    const query = "select salt, password from members where memberid = $1";
    const values = [req.decoded.memberid];

    pool
      .query(query, values)
      .then((result) => {
        if (generateHash(old_password, result.rows[0].salt) != result.rows[0].password) {
          res.status(400).send({
            message: "Old Password Does Not Match",
          });
          return;
        }

        // check if password meets minimum strength requirements
        if (!isValidPassword(new_password)) {
          res.status(400).send({
            message: "Password Does Not Meet Minimum Requirements",
          });
          return;
        }

        const salt = generateSalt(32);
        const salted_hash = generateHash(new_password, salt);

        const query = "update members set password = $1, salt = $2 where memberid = $3 returning email";
        const values = [salted_hash, salt, req.decoded.memberid];

        pool.query(query, values).then((result) => {
          res.status(200).send({
            success: true,
            message: "Password Successfully Changed!",
          });
        });
      })
      .catch((err) => {
        console.log(err);
        res.status(400).send({
          message: "Error Changing Password",
        });
      });
  } else {
    res.status(400).send({
      message: "Missing Required Information",
    });
  }
});

module.exports = router;
