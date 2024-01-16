const express = require("express")
const connectDb = require("./config/dbConnection")
const errorHandler = require("./middleware/errorHandler")
const dotenv = require("dotenv").config()
const cors = require("cors");
const corsOptions = require("./config/corsOptions");

connectDb();
const app = express()

// Cross Origin Resource Sharing
app.use(cors(corsOptions));

const port = process.env.PORT || 5000

app.use(express.json())
app.use("/api/users", require("./routes/userRoutes"));
app.use(errorHandler)

app.listen(port, () => {
  console.log(`Server running on port ${port}`)
})