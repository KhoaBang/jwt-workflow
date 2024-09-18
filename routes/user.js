const express = require("express");
const router = express.Router();
const pool = require("../util/database");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const authenticateToken = require("../util/authenticateToken"); // hàm để validate jwt

/*
Route để test authenciation
*/
router.get("/protected", authenticateToken, (req, res) => {
  const user = req.user; 
  res.status(200).send(`Welcome to protected route ${user.email}`);
});

/* 
Signup 
*/
router.post("/register", async function (req, res) {
  const { username, email, password } = req.body;

  // kiểm tra regex cho password và email
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

  // mã hoá password và gửi cho database
  try {
    const encryptedPassword = await bcrypt.hash(password, 10);

    const sqlQuery =
      "INSERT INTO info (username, email, password) VALUES (?,?,?)";
    await pool.query(sqlQuery, [
      username,
      email,
      encryptedPassword,
    ]);

    res.status(201).json({ status: "success" });
  } catch (error) {
    if (error.code === "ER_DUP_ENTRY")
      res.status(400).json({ code: 9996, message: "email used" });
    else {
      res.status(400).send(error.message);
    }
  }
});

/* 
Login 
*/
router.post("/login", async function (req, res) {
  try {
    const { email, password } = req.body;

    // Tìm người dùng từ DB
    const sqlGetUser = " SELECT * FROM info WHERE email=?";
    const rows = await pool.query(sqlGetUser, email);

    if (rows.length > 0) {
      const {id, username, email}= rows[0]
      const isValid = await bcrypt.compare(password, rows[0].password);

      // tạo token nếu thông tin đăng nhập thoả mãn
      if (isValid) {
        const accessToken = jwt.sign( // tạo access token
          { username: username, email: email, id: id },
          process.env.ACCESS_TOKEN_SECRET,
          { expiresIn: "1h" }
        );
        const refreshToken = jwt.sign( // tạo refresh token
          { username: username, email: email, id: id },
          process.env.REFRESH_TOKEN_SECRET,
          { expiresIn: "7d" }
        );

        
        // gửi refresh token mới tạo cho DB
        try {
          const tkDB = await pool.query( // kiểm tra tồn tại
            "SELECT 1 FROM refresh_tokens WHERE id =? LIMIT 1",
            [id]
          );
          console.log("here "+tkDB.length)
          if (tkDB.length === 0) { // nếu không tồn tại => Tạo mới và lưu
            const rep = await pool.query(
              "INSERT INTO refresh_tokens (token, id, status) VALUES (?,?,?)",
              [refreshToken, id, "active"]
            );
            console.log(rep)
          } else { // nếu tồn tại => Cập nhật
            await pool.query(
              "UPDATE refresh_tokens SET token=?, status =? WHERE id =?",
              [refreshToken, "active", id]
            );
          }
        } catch (dbErr) {
          return res.status(500).send(dbErr);
        }

        // Trả lại thông tin cho client
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

/* 
Route để cấp mới refresh token và access token khi access token cũ hết hiệu lực
*/
router.post("/refresh", async function (req, res) { 
  const { refreshToken } = req.body;
  if (!refreshToken) {
    return res.status(400).json({ message: "Refresh token is required." });
  }
  // kiểm tra hiệu lực của refreshToken được gửi lên
  jwt.verify(
    refreshToken,
    process.env.REFRESH_TOKEN_SECRET,
    async (err, decoded) => {
      if (err) {
        return res
          .status(403)
          .json({ message: "invalid refresh token, please login again" });
      }
      // kiểm tra trạng thái của refreshToken này trong DB
      try {
        const status = await pool.query(
          "SELECT status FROM refresh_tokens WHERE token=?",
          [refreshToken]
        );
        if (status[0].status === "active") {
          // Nếu còn hiệu lực, tạo mới refresh token và lưu vào DB với status active, tạo mới access tk và gửi cho client
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

/* 
Logout
*/
router.post("/logout", async (req, res) => { // người dùng log out bằng cách gửi refresh token vào route này
  const { refreshToken } = req.body;
  if (!refreshToken) {
    return res.status(400).json({ message: "Refresh token is required." });
  }
  jwt.verify( // kiểm tra hiệu lực của refresh token
    refreshToken,
    process.env.REFRESH_TOKEN_SECRET,
    async (err, decoded) => {
      if (err) {
        return res
          .status(403)
          .json({ message: "invalid refresh token, please login again to get new refresh token" });
      }
      try { // nếu refresh token còn hiệu lực, thực hiện log out cho client bằng cách chuyển status của refresh token đó trong DB thành revoked
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
        console.error(dberr); 
        return res.status(500).json({ message: "Token database error." });
      }
      return res.status(200).json({ message: "Logged out successfully." });
    }
  );
});

module.exports = router;
