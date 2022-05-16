const express = require("express");
const router = express.Router();

const middleware = require("../../middleware");
const jwt = require("jsonwebtoken");

const pool = require("../../utilities").pool;
const path = require("path");

const remove = (memberid) => {
  const query = "delete from members where memberid = $1";
  const values = [memberid];

  // delete user from the database
  pool.query(query, values);
};

/**
 * @api {post} /auth/verify Request to send "account verification" email to user
 * @apiName VerifyAccount
 * @apiGroup Verification
 *
 * @apiParam {String} email the email to send the account verification link to
 *
 * @apiSuccess (200: Success) {boolean} success whether the email was sent
 * @apiSuccess (200: Success) {String} message "Verification Email Successfully Sent!"
 * @apiSuccess (200: Success) {String} email where the account verification email was sent
 *
 * @apiError (400: Invalid Email) {String} message "Invalid Email"
 * @apiError (404: User Not Found) {String} message "User Not Found"
 *
 */
router.post("/", (req, res) => {
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

      sendVerificationEmail(req.body.email, token, (err) => {
        if (err) {
          res.status(400).send({
            message: "Invalid Email",
          });
          console.log(err);
          return;
        } else {
          res.status(200).send({
            success: true,
            message: "Verification Email Successfully Sent!",
            email: req.body.email,
          });
        }
      });
    }
  });
});

/**
 * @api {get} /auth/verify Request to verify a user
 * @apiName Verify
 * @apiGroup Verification
 *
 * @apiHeader {String} authorization JWT provided from /auth/verify post
 *
 * @apiSuccess (200: Success) {boolean} success whether credentials match
 * @apiSuccess (200: Success) {String} message "Successfully Verified Email!!"
 * @apiSuccess (200: Success) {String} email the verified email
 *
 *  * @apiSuccessExample {json} Success-Response:
 *     HTTP/1.1 200 OK
 *     {
 *       "success": true,
 *       "message": "Successfully Verified Email!",
 *       "email": "fastchat@mail.com"
 *     }
 *
 * @apiError (400: Error Verifying Email) {String} message "Error Verifying Email"
 * @apiError (400: Email Already Verified) {String} message "Email Already Verified"
 *
 * @apiError (403: Invalid/Expired JWT) {String} message "JWT Invalid or Expired"
 */
router.put(
  "/",
  middleware.checkToken,
  (req, res, next) => {
    const query = "select * from members where verification = 0 and memberid = $1";
    const values = [req.decoded.memberid];

    pool
      .query(query, values)
      .then((result) => {
        if (result.rowCount == 0) {
          res.status(400).send({
            message: "Email Already Verified",
          });
        } else {
          next();
        }
      })
      .catch((err) => {
        res.status(400).send({
          message: "Error Verifying Email",
        });
      });
  },
  (req, res) => {
    const query = "update members set verification = 1 where memberid = $1";
    const values = [req.decoded.memberid];

    pool
      .query(query, values)
      .then((result) => {
        res.status(200).send({
          success: true,
          message: "Successfully Verified Email!",
          email: req.decoded.email,
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

/**
 * Static HTML page for communicating successful account verification.
 */
router.get("/success", (req, res) => {
  res.sendFile(path.join(__dirname, "../../html/verification", "verificationsuccess.html"));
});

/**
 * Static HTML page for communicating a failed verification attempt.
 */
router.get("/failure", (req, res) => {
  res.sendFile(path.join(__dirname, "../../html/verification", "verificationfailure.html"));
});

/**
 * Static HTML page for verifying account.
 */
router.get("/:token", (req, res) => {
  jwt.verify(req.params.token, process.env.JSON_WEB_TOKEN, (err) => {
    if (err) {
      res.sendFile(path.join(__dirname, "../../html/verification", "verificationfailure.html"));
    } else {
      res.sendFile(path.join(__dirname, "../../html/verification", "verification.html"));
    }
  });
});

module.exports = router;
