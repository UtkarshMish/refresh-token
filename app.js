const express = require("express");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
if (process.env.NODE_ENV !== 'production') {
  require('dotenv').config();
}
// CONST, Variables or Objects
app = express();
const SECRET_KEY = process.env.SECRET_KEY;
let AUTH_KEY = process.env.Auth_KEY;
const PORT = 4000;

//Used Functions
function generate(pwdToken) {
  return jwt.sign(pwdToken, AUTH_KEY);
}

function verify(password) {
  try {
    return !!(jwt.verify(password, AUTH_KEY));
  } catch (JsonWebTokenError) {
    return false;
  }
}


//Login API
app.post("/login", async function userAuth(request, response) {
  const {password} = request.query;
  const pwdToken = jwt.sign(password, SECRET_KEY);
  const refreshToken = generate(pwdToken);

  return response.send({
    token: pwdToken,
    refresh_token: refreshToken,
  });
});

//Refresh TOKEN
app.post("/api/token-generator", async function genToken(request, response) {
  const {refresh_token} = request.query;

  const password = jwt.decode(refresh_token, AUTH_KEY);
  const auth = verify(refresh_token);
  if (auth === true) {
    AUTH_KEY = crypto.randomBytes(20).toString("hex");

    const newToken = generate(password);
    return response.send({
      value: auth,
      refresh_token: newToken,
    });
  } else {
    return response.send({
      value: auth,
    });
  }
});

app.listen(PORT, () => console.log(`server started at ${PORT}:==`));
