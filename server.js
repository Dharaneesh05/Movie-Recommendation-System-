const express = require("express")
const mongoose = require("mongoose")
const nodemailer = require("nodemailer")
const dotenv = require("dotenv")
const path = require("path")
const bcrypt = require("bcryptjs")
const jwt = require("jsonwebtoken")

const app = express()
dotenv.config()

if (!process.env.JWT_SECRET) {
  console.error("❌ JWT_SECRET is not defined in .env")
  process.exit(1)
}
if (!process.env.EMAIL_USER || !process.env.EMAIL_PASS) {
  console.error("❌ EMAIL_USER or EMAIL_PASS is not defined in .env")
  process.exit(1)
}
console.log("✅ .env loaded: JWT_SECRET, EMAIL_USER, EMAIL_PASS are set")
app.use(express.json())
app.use(express.static(path.join(__dirname, "public")))

const otpStore = {}
const UserSchema = new mongoose.Schema({
  username: String,
  email: { type: String, unique: true, required: true },
  password: String,
  dob: String,
  number: String,
  language: String,
  preferences: [String],
})

const User = mongoose.model("User", UserSchema)


mongoose
  .connect("mongodb://127.0.0.1:27017/movieReviewSystem", {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => {
    console.log("Connected to MongoDB")
  })
  .catch((err) => {
    console.error("MongoDB connection error:", err.message)
    process.exit(1)
  })

const transporter = nodemailer.createTransport({
  host: "smtp.gmail.com",
  port: 587,
  secure: false,
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
})


const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"]
  const token = authHeader && authHeader.split(" ")[1]
  if (!token) return res.status(401).json({ success: false, message: "No token provided" })

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ success: false, message: "Invalid token" })
    req.user = user
    next()
  })
}


app.post("/api/generate-otp", async (req, res) => {
  const { email } = req.body
  const normalizedEmail = email.toLowerCase()
  if (!normalizedEmail || !normalizedEmail.includes("@")) {
    console.log("Invalid email provided for OTP:", email)
    return res.status(400).json({ message: "Invalid email" })
  }

  const otp = Math.floor(1000 + Math.random() * 9000)
  const expires = new Date(Date.now() + 10 * 60 * 1000)
  otpStore[normalizedEmail] = { otp, expires }

  try {
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: normalizedEmail,
      subject: "Your OTP for CINEFELLAS Registration",
      text: `Your OTP is: ${otp}. It expires in 10 minutes.`,
    })
    console.log(`OTP sent to ${normalizedEmail}: ${otp}`)
    res.json({ message: "OTP sent" })
  } catch (err) {
    console.error("Email sending error:", err.message)
    res.status(500).json({ message: "Failed to send OTP", error: err.message })
  }
})


app.post("/api/register", async (req, res) => {
  const { username, email, password, dob, number, language, preferences, otp } = req.body
  const normalizedEmail = email.toLowerCase()
  console.log("Registration attempt:", { email: normalizedEmail, username, dob, number, language, preferences })

 
  const record = otpStore[normalizedEmail]
  if (!record) {
    console.log("No OTP record found for:", normalizedEmail)
    return res.status(400).json({ message: "No OTP generated for this email" })
  }
  if (record.otp !== Number.parseInt(otp)) {
    console.log("OTP mismatch:", { provided: otp, expected: record.otp })
    return res.status(400).json({ message: "Invalid OTP" })
  }
  if (new Date() > record.expires) {
    console.log("OTP expired for:", normalizedEmail)
    return res.status(400).json({ message: "OTP expired" })
  }

  try {
    const existingUser = await User.findOne({ email: { $regex: new RegExp("^" + normalizedEmail + "$", "i") } })
    if (existingUser) {
      console.log(`Registration failed: Email already exists - ${normalizedEmail}`)
      return res.status(400).json({ message: "Email already registered" })
    }


    const hashedPassword = await bcrypt.hash(password, 10)
    const user = new User({
      username,
      email: normalizedEmail,
      password: hashedPassword,
      dob,
      number,
      language,
      preferences: Array.isArray(preferences) ? preferences : preferences.split(",").map((p) => p.trim()),
    })
    await user.save()
    console.log(`User registered successfully: ${normalizedEmail}, ID: ${user._id}`)
    delete otpStore[normalizedEmail]
    res.json({ success: true })
  } catch (err) {
    console.error("Registration error:", err.message)
    res.status(500).json({ message: "Registration failed", error: err.message })
  }
})


app.post("/api/login", async (req, res) => {
  const { email, password } = req.body
  if (!email || !password) {
    console.log("Missing email or password:", { email, password })
    return res.status(400).json({ success: false, message: "Email and password are required" })
  }
  try {
    console.log("Login attempt:", { email })
    const normalizedEmail = email.toLowerCase()
    const user = await User.findOne({ email: { $regex: new RegExp("^" + normalizedEmail + "$", "i") } })
    if (!user) {
      console.log("User not found:", normalizedEmail)
      return res.status(401).json({ success: false, message: "Invalid email or password" })
    }
    console.log("User found:", { email: normalizedEmail, userId: user._id, storedPassword: user.password })

    if (!user._id) {
      console.error("User ID missing for:", normalizedEmail)
      return res.status(500).json({ success: false, message: "Invalid user data: missing ID" })
    }
    if (!process.env.JWT_SECRET) {
      console.error("JWT_SECRET not set during login")
      return res.status(500).json({ success: false, message: "Server configuration error" })
    }
    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: "1h" })
    console.log("Login successful:", { email: normalizedEmail, userId: user._id })
    res.status(200).json({ success: true, token })
  } catch (err) {
    console.error("Login error:", err.message)
    res.status(500).json({ success: false, message: "Server error during login", error: err.message })
  }
})

app.post("/api/request-password-reset", async (req, res) => {
  const { email } = req.body
  const normalizedEmail = email.toLowerCase()
  if (!normalizedEmail || !normalizedEmail.includes("@")) {
    console.log("Invalid email for password reset:", email)
    return res.status(400).json({ message: "Invalid email" })
  }
  const user = await User.findOne({ email: { $regex: new RegExp("^" + normalizedEmail + "$", "i") } })
  if (!user) {
    console.log("User not found for password reset:", normalizedEmail)
    return res.status(404).json({ message: "Invalid email or password" })
  }
  const otp = Math.floor(1000 + Math.random() * 9000)
  const expires = new Date(Date.now() + 10 * 60 * 1000)
  otpStore[normalizedEmail] = { otp, expires, type: "password-reset" }
  try {
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: normalizedEmail,
      subject: "Password Reset OTP for CINEFELLAS",
      text: `Your OTP for password reset is: ${otp}. It expires in 10 minutes.`,
    })
    console.log(`Password reset OTP sent to ${normalizedEmail}: ${otp}`)
    res.json({ message: "Password reset OTP sent" })
  } catch (err) {
    console.error("Email sending error:", err.message)
    res.status(500).json({ message: "Failed to send OTP", error: err.message })
  }
})


app.post("/api/reset-password", async (req, res) => {
  const { email, otp, newPassword } = req.body
  const normalizedEmail = email.toLowerCase()
  const record = otpStore[normalizedEmail]
  if (
    !record ||
    record.otp !== Number.parseInt(otp) ||
    new Date() > record.expires ||
    record.type !== "password-reset"
  ) {
    console.log("Invalid or expired OTP for password reset:", { email: normalizedEmail, providedOtp: otp })
    return res.status(400).json({ message: "Invalid or expired OTP" })
  }
  try {
    const hashedPassword = await bcrypt.hash(newPassword, 10)
    await User.updateOne(
      { email: { $regex: new RegExp("^" + normalizedEmail + "$", "i") } },
      { $set: { password: hashedPassword } },
    )
    console.log(`Password reset for: ${normalizedEmail}`)
    delete otpStore[normalizedEmail]
    res.json({ success: true, message: "Password reset successful" })
  } catch (err) {
    console.error("Password reset error:", err.message)
    res.status(500).json({ message: "Password reset failed", error: err.message })
  }
})


app.get("/api/user", authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId).select("username preferences language")
    if (!user) {
      console.log("User not found for fetch:", req.user.userId)
      return res.status(404).json({ success: false, message: "User not found" })
    }
    res.json({ success: true, user })
  } catch (err) {
    console.error("User fetch error:", err.message)
    res.status(500).json({ success: false, message: "Server error" })
  }
})

app.listen(3000, () => console.log("Server running on port 3000"))
