const asyncHandler = require("express-async-handler")
const User = require("../models/user")
const jwt = require("jsonwebtoken")

//@desc Get all users
//@route GET /api/users
//@access public
const getAllUsers = asyncHandler(async (req, res) => {
  const allUsers = await User.find()
  res.status(200).json(allUsers)
});

//@desc Register a new user
//@route POST /api/users/register
//@access public
const registerUser = asyncHandler(async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) {
    res.status(400)
    throw new Error("All fields are mandatory!")
  }

  const userAvailable = await User.findOne({ email })
  if (userAvailable) {
    res.status(400);
    throw new Error("A User with the provided email already exists!");
  }

  const newUser = await User.create({
    name,
    email,
    password
  })
  console.log(`User created: ${newUser}`)

  if (newUser) {
    res.status(201).json({ _id: newUser.id, email: newUser.email })
  }else {
    res.status(400)
    throw new Error("User data is not valid")
  }
});

//@desc Log in the user
//@route POST /api/users/login
//@access public
const loginUser = asyncHandler(async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    res.status(400)
    throw new Error("All fields are mandatory!")
  }

  const user = await User.findOne({ email, password });
  if (user) {
    const accessToken = jwt.sign({
      user: {
          name: user.name,
          email: user.email,
          id: user.id
        },
      }, 
      process.env.ACCESS_TOKEN_SECRET,
      { expiresIn: "30m"}
    )
    res.status(200).json({ accessToken })
  } else {
    res.status(401)
    throw new Error("Invalid Credentials")
  }
});

//@desc Get logged-in user info
//@route POST /api/users/current
//@access private
const getLoggedInUserInfo = asyncHandler(async (req, res) => {
  console.log("User wants to fetch their information")
  res.json(req.user);
});

module.exports = { getAllUsers, registerUser, loginUser, getLoggedInUserInfo };