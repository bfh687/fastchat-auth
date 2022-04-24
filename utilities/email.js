const nodemailer = require("nodemailer");
const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
        user: "fastchatauth@gmail.com",
        pass: process.env.EMAIL_PWD,
    },
});

const server_url = "https://fastchat-auth.herokuapp.com";
const local_url = "http://localhost:5000";

const sendVerificationEmail = (receiver, token) => {
    const mail = {
        from: "fastchatauth@gmail.com",
        to: receiver,
        subject: "Verify your FastChat account!",
        text:
            "Please verify your account by clicking on the following link: \n" +
            `${local_url}/auth/verify/${token}` +
            "\n\nIf you did not initiate this request, please ignore this email.",
    };

    transporter.sendMail(mail, (err, info) => {
        if (err) {
            console.log(err);
            return false;
        } else {
            console.log("email sent: " + info.response);
            return true;
        }
    });
};

module.exports = {
    sendVerificationEmail,
};
