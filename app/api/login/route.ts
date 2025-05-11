import { NextResponse } from "next/server"
import bcrypt from "bcryptjs"
import jwt from "jsonwebtoken"
import dbConnect from "@/lib/mongodb"
import User from "@/models/User"

export async function POST(request: Request) {
  try {
    await dbConnect()

    const { email, password } = await request.json()

    if (!email || !password) {
      console.log("Missing email or password:", { email, password })
      return NextResponse.json({ success: false, message: "Email and password are required" }, { status: 400 })
    }

    console.log("Login attempt:", { email })
    const normalizedEmail = email.toLowerCase()

    const user = await User.findOne({
      email: { $regex: new RegExp("^" + normalizedEmail + "$", "i") },
    })

    if (!user) {
      console.log("User not found:", normalizedEmail)
      return NextResponse.json({ success: false, message: "Invalid email or password" }, { status: 401 })
    }

    console.log("User found:", { email: normalizedEmail, userId: user._id })

    // Verify password
    const isPasswordValid = await bcrypt.compare(password, user.password)
    if (!isPasswordValid) {
      console.log("Invalid password for user:", normalizedEmail)
      return NextResponse.json({ success: false, message: "Invalid email or password" }, { status: 401 })
    }

    if (!user._id) {
      console.error("User ID missing for:", normalizedEmail)
      return NextResponse.json({ success: false, message: "Invalid user data: missing ID" }, { status: 500 })
    }

    if (!process.env.JWT_SECRET) {
      console.error("JWT_SECRET not set during login")
      return NextResponse.json({ success: false, message: "Server configuration error" }, { status: 500 })
    }

    const token = jwt.sign({ userId: user._id.toString() }, process.env.JWT_SECRET, { expiresIn: "1h" })

    console.log("Login successful:", { email: normalizedEmail, userId: user._id })

    return NextResponse.json({ success: true, token })
  } catch (err) {
    console.error("Login error:", err)
    return NextResponse.json(
      { success: false, message: "Server error during login", error: err instanceof Error ? err.message : String(err) },
      { status: 500 },
    )
  }
}
