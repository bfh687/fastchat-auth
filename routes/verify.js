const express = require("express");
const router = express.Router();

const jwt = require("jsonwebtoken");
const pool = require("../utilities").pool;

router.put(
    "/:token",
    (req, res, next) => {
        const token = req.params.token;

        jwt.verify(token, process.env.JSON_WEB_TOKEN, (err, decoded) => {
            if (err) {
                return res.status(403).json({
                    success: false,
                    message: "token is not valid",
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

        pool.query(query, values)
            .then((result) => {
                res.status(200).send({
                    success: true,
                    message: `successfully verified ${req.decoded.email}`,
                });
            })
            .catch((err) => {
                res.status(400).send({
                    message: "error verifying email, please try again",
                });
            });
    }
);

module.exports = router;
