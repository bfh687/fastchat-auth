const nodemailer = require("nodemailer");
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: "fastchatauth@gmail.com",
    pass: process.env.EMAIL_PWD,
  },
});

const sendVerificationEmail = (receiver, token, callback) => {
  const mail = {
    from: "fastchatauth@gmail.com",
    to: receiver,
    subject: "Verify your FastChat account!",
    text:
      "Please verify your account by clicking on the following link: \n" +
      `${process.env.DOMAIN_URL}/auth/verify/${token}` +
      "\n\nIf you did not initiate this request, please ignore this email.",
  };

  transporter.sendMail(mail, (err, info) => {
    callback(err);
  });
};

const sendPasswordResetEmail = (receiver, token, callback) => {
  const mail = {
    from: "fastchatauth@gmail.com",
    to: receiver,
    subject: "Reset Your FastChat Account Password!",
    text:
      "Please visit the following link to reset your password: \n" +
      `${process.env.DOMAIN_URL}/auth/password/reset/${token}` +
      "\n\nIf you did not initiate this request, we suggest changing your FastChat account password as soon as possible",
  };

  transporter.sendMail(mail, (err, info) => {
    callback(err);
  });
};

module.exports = {
  sendVerificationEmail,
  sendPasswordResetEmail,
};
