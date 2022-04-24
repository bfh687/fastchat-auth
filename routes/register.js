const express = require("express");
const router = express.Router();

const pool = require("../utilities").pool;

const validation = require("../utilities").validation;
let isStringProvided = validation.isStringProvided;

const generateHash = require("../utilities").generateHash;
const generateSalt = require("../utilities").generateSalt;

const sendEmail = require("../utilities").sendEmail;

router.post("/", (req, res, next) => {
    res.status(200).send({
        message: "placeholder endpoint",
    });
});

module.exports = router;
