// http client
const express = require("express");
const app = express();

// connection to db
const pool = require("./utilities").pool;

// import middleware (performs intermediate steps before request is received)
const middleware = require("./middleware");

app.use(express.json());
app.use(middleware.jsonErrorInBody);

// auth routes
app.use("/auth", require("./routes/login.js"));
app.use("/auth", require("./routes/register.js"));
app.use("/auth/verify", require("./routes/verify.js"));

/*
 * Serve the API documentation generated by apidoc as HTML.
 * https://apidocjs.com/
 */
// app.use("/doc", express.static('apidoc'))

app.listen(process.env.PORT || 5000, () => {
    console.log("Server up and running on port: " + (process.env.PORT || 5000));
});
