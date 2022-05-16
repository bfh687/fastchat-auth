const express = require("express");
const router = express.Router();

const jwt = require("jsonwebtoken");
const pool = require("../../utilities").pool;
const path = require("path");

const remove = (memberid) => {
  const query = "delete from members where memberid = $1";
  const values = [memberid];

  // delete user from the database
  pool.query(query, values);
};

router.get("/success", (req, res) => {
  res.sendFile(path.join(__dirname, "../../html/password", "passwordresetsuccess.html"));
});

router.get("/failure", (req, res) => {
  res.sendFile(path.join(__dirname, "../../html/password", "passwordresetfailure.html"));
});

/**
 * @api {get} /auth/verify/:id Request to verify a user
 * @apiName Verify
 * @apiGroup Auth
 *
 * @apiParam {String} id a signed JWT
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
 *       "token": "fastchat@mail.com"
 *     }
 *
 * @apiError (400: Error Verifying Email) {String} message "Error Verifying Email"
 * @apiError (400: Email Already Verified) {String} message "Email Already Verified"
 *
 * @apiError (403: Invalid/Expired JWT) {String} message "JWT Invalid or Expired"
 */
router.get(
  "/:token",
  (req, res, next) => {
    const token = req.params.token;

    jwt.verify(token, process.env.JSON_WEB_TOKEN, { ignoreExpiration: true }, (err, decoded) => {
      // most likely JWT is expired
      const curr_time = new Date().getTime() / 1000;
      if (err || decoded.exp < curr_time) {
        // check if user is already verified.
        const query = "select * from members where memberid = $1 and verification = 1";
        const values = [decoded.memberid];

        pool
          .query(query, values)
          .then((result) => {
            // user is unverified, remove user from database
            if (result.rowCount == 0) {
              remove(decoded.memberid);

              res.status(403).send({
                message: "JWT Invalid or Expired",
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

module.exports = router;
