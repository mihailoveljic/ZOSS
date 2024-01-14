const express = require("express")
const router = express.Router()
const { getAllUsers, registerUser, loginUser, getLoggedInUserInfo } = require("../controllers/userController");
const validateToken = require("../middleware/validateTokenHandler");

router.route("/").get(getAllUsers);

router.post("/register", registerUser)

router.post("/login", loginUser);

router.get("/current", validateToken, getLoggedInUserInfo);

module.exports = router;