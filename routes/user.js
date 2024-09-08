const express = require("express");
const router = express.Router();
const pool = require("../util/database");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const authenticateToken = require("../util/authenticateToken");

router.get("/protected", authenticateToken, (req, res) => {
  const user = req.user; // Provided by the authenticateToken middleware
  res.status(200).send(`Welcome to protected route ${user.email}`);
});

/** Signup */
router.post("/register", async function (req, res) {
  const { username, email, password } = req.body;

  // check regex for password and email
  const emailPattern = /^[\w-\.]+@([\w-]+\.)+[\w-]{2,4}$/;
  const passwordPattern = /^.{6,10}$/;

  if (!emailPattern.test(email)) {
    return res.status(400).json({ message: "invalid email address" });
  }
  if (!passwordPattern.test(password)) {
    return res
      .status(400)
      .json({ message: "password must has between 6 and 10 characters" });
  }

  // send to db
  try {
    const encryptedPassword = await bcrypt.hash(password, 10);

    const sqlQuery =
      "INSERT INTO info (username, email, password) VALUES (?,?,?)";
    const result = await pool.query(sqlQuery, [
      username,
      email,
      encryptedPassword,
    ]);

    res.status(201).json({ inserted: Number(result.insertId) }); // ID in mariadb is BIGINT => use Number() to convert to normal num
  } catch (error) {
    if (error.code === "ER_DUP_ENTRY")
      res.status(400).json({ code: 9996, message: "email used" });
    else {
      res.status(400).send(error.message);
    }
  }
});

router.post("/login", async function (req, res) {
  try {
    const { email, password } = req.body;

    // fetch user from db
    const sqlGetUser = " SELECT * FROM info WHERE email=?";
    const rows = await pool.query(sqlGetUser, email);

    if (rows.length > 0) {
      const isValid = await bcrypt.compare(password, rows[0].password);

      // create jwt if login attemp is valid
      if (isValid) {
        const accessToken = jwt.sign(
          { username: rows[0].username, email: rows[0].email, id: rows[0].id },
          process.env.ACCESS_TOKEN_SECRET,
          { expiresIn: "1h" }
        );
        const refreshToken = jwt.sign(
          { username: rows[0].username, email: rows[0].email, id: rows[0].id },
          process.env.REFRESH_TOKEN_SECRET,
          { expiresIn: "7d" }
        );

        //store or update the correspond regreshtk to database with active status
        try {
          const tkDB = await pool.query(
            "SELECT 1 FROM refresh_tokens WHERE user_email =? LIMIT 1",
            [rows[0].email]
          );
          if (tkDB.length === 0) {
            await pool.query(
              "INSERT INTO refresh_tokens (token, user_email, status) VALUES (?,?,?)",
              [refreshToken, rows[0].email, "active"]
            );
          } else {
            await pool.query(
              "UPDATE refresh_tokens SET token=?, status =? WHERE user_email =?",
              [refreshToken, "active", rows[0].email]
            );
          }
        } catch (dbErr) {
          return res.status(500).send("Token database error");
        }

        res.status(200).json({
          username: rows[0].username,
          email: rows[0].email,
          id: rows[0].id,
          accessToken,
          refreshToken,
        });
      }
    } else {
      res.status(400).send(`user with email ${email} was not found`);
    }
  } catch (error) {
    res.status(400).send(error.message);
  }
});

router.post("/refresh", async function (req, res) {
  const { refreshToken } = req.body;
  if (!refreshToken) {
    return res.status(400).json({ message: "Refresh token is required." });
  }
  // check if user's refreshToken is valid
  jwt.verify(
    refreshToken,
    process.env.REFRESH_TOKEN_SECRET,
    async (err, decoded) => {
      if (err) {
        return res
          .status(403)
          .json({ message: "invalid refresh token, please login again" });
      }
      // if valid check if the refresh token is active or revoked
      try {
        const status = await pool.query(
          "SELECT status FROM refresh_tokens WHERE token=?",
          [refreshToken]
        );
        if (status[0].status === "active") {
          // if the token is still active, create and store new refresh tk then issue new access tk
          const sqlGetUser = " SELECT * FROM info WHERE email=?";
          const rows = await pool.query(sqlGetUser, decoded.email);

          if (rows.length > 0) {
            const newAccessToken = jwt.sign(
              {
                username: rows[0].username,
                email: rows[0].email,
                id: rows[0].id,
              },
              process.env.ACCESS_TOKEN_SECRET,
              { expiresIn: "1h" }
            );
            const newRefreshToken = jwt.sign(
              {
                username: rows[0].username,
                email: rows[0].email,
                id: rows[0].id,
              },
              process.env.REFRESH_TOKEN_SECRET,
              { expiresIn: "7d" }
            );
            await pool.query(
              "UPDATE refresh_tokens SET token=?, status =? WHERE user_email =?",
              [newRefreshToken, "active", rows[0].email]
            );
            return res.status(200).json({ newRefreshToken, newAccessToken });
          } else {
            res.status(403).send(`user was not found`);
          }
        } else {
          return res.status(403).send(`REVOKED TOKEN USAGE`);
        }
      } catch (dberr) {
        return res.status(500).send("Token database error");
      }
    }
  );
});

router.post("/logout", async (req, res) => {
  const { refreshToken } = req.body;
  if (!refreshToken) {
    return res.status(400).json({ message: "Refresh token is required." });
  }
  jwt.verify(
    refreshToken,
    process.env.REFRESH_TOKEN_SECRET,
    async (err, decoded) => {
      if (err) {
        return res
          .status(403)
          .json({ message: "invalid refresh token, please login again" });
      }
      try {
        const user = await pool.query(
          "SELECT * FROM refresh_tokens WHERE token=?",
          [refreshToken]
        );
 
        if (user.length > 0) {
          const { user_email } = user[0];
          await pool.query(
            "UPDATE refresh_tokens SET status =? WHERE user_email =?",
            ['revoked', user_email]
          );
        } else {
          return res.status(403).send("refreshToken not found");
        }
      } catch (dberr) {
        console.error(dberr); // Log database error for debugging
        return res.status(500).json({ message: "Token database error." });
      }
      return res.status(200).json({ message: "Logged out successfully." });
    }
  );
});

module.exports = router;
