const express = require("express");
const router = express.Router();

const pool = require("../../utilities/exports").pool;
const path = require("path");

const validation = require("../../utilities/exports").validation;
const isStringProvided = validation.isStringProvided;
const isValidPassword = validation.isValidPassword;

const middleware = require("../../middleware");
const jwt = require("jsonwebtoken");

const generateHash = require("../../utilities/exports").generateHash;
const generateSalt = require("../../utilities/exports").generateSalt;

const sendPasswordResetEmail = require("../../utilities/exports").sendPasswordResetEmail;

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
 * @apiError (400: Old Password Does Not Match) {String} message "Old Password Does Not Match The Password In The Database"
 * @apiError (400: Password Does Not Meet Requirements) {String} message "Password Does Not Meet Minimum Requirements"
 * @apiError (400: Old Password Does Not Match) {String} message "Old Password Does Not Match"
 * @apiError (400: Error Changing Password) {String} message "Error Changing Password"
 * @apiError (400: Missing Parameters) {String} message "Missing Required Information"
 *
 */
router.post("/", middleware.checkToken, (req, res) => {
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

// sends a password reset email to the given user's email (if they exist)
router.post("/forgot", (req, res) => {
  const query = "select * from members where email = $1";
  const values = [req.body.email];

  pool.query(query, values).then((result) => {
    if (result.rowCount == 0) {
      res.status(404).send({
        message: "User Not Found",
      });
    } else {
      const token = jwt.sign(
        {
          memberid: result.rows[0].memberid,
          email: result.rows[0].email,
        },
        process.env.JSON_WEB_TOKEN,
        {
          expiresIn: "10m",
        }
      );

      sendPasswordResetEmail(req.body.email, token, (err) => {
        if (err) {
          res.status(400).send({
            message: "Invalid Email",
          });
          console.log(err);
          return;
        } else {
          res.status(200).send({
            success: true,
            message: "Password Reset Email Successfully Sent!",
            email: req.body.email,
          });
        }
      });
    }
  });
});

// resets user password
router.post("/reset", middleware.checkToken, (req, res) => {
  const salt = generateSalt(32);
  const salted_hash = generateHash(req.body.password, salt);

  const query = "update members set salt = $1, password = $2 where memberid = $3";
  const values = [salt, salted_hash, req.decoded.memberid];

  pool
    .query(query, values)
    .then((result) => {
      res.status(200).send({
        success: true,
        message: "Successfully Reset Password!",
        email: req.decoded.email,
      });
    })
    .catch((err) => {
      res.status(400).send({
        message: "Error Resetting Password",
      });
    });
});

router.get("/reset/success", (req, res) => {
  res.sendFile(path.join(__dirname, "../../html/password", "passwordresetsuccess.html"));
});

router.get("/reset/failure", (req, res) => {
  res.sendFile(path.join(__dirname, "../../html/password", "passwordresetfailure.html"));
});

router.get("/reset/:token", (req, res) => {
  jwt.verify(req.params.token, process.env.JSON_WEB_TOKEN, (err, decoded) => {
    if (err) {
      res.sendFile(path.join(__dirname, "../../html/password", "passwordresetfailure.html"));
    } else {
      res.sendFile(path.join(__dirname, "../../html/password", "passwordresetreset.html"));
    }
  });
});

module.exports = router;
