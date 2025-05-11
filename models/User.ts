import mongoose from "mongoose"

// MongoDB User Schema with unique index on email
const UserSchema = new mongoose.Schema({
  username: String,
  email: { type: String, unique: true, required: true },
  password: String,
  dob: String,
  number: String,
  language: String,
  preferences: [String],
})

export default mongoose.models.User || mongoose.model("User", UserSchema)
