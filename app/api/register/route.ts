import { NextResponse } from "next/server"
import bcrypt from "bcryptjs"
import dbConnect from "@/lib/mongodb"
import User from "@/models/User"
import { otpStore } from "../generate-otp/route"

export async function POST(request: Request) {
  try {
    await dbConnect()

    const { username, email, password, dob, number, language, preferences, otp } = await request.json()
    const normalizedEmail = email.toLowerCase()

    console.log("Registration attempt:", { email: normalizedEmail, username, dob, number, language, preferences })

    // Validate OTP
    const record = otpStore[normalizedEmail]
    if (!record) {
      console.log("No OTP record found for:", normalizedEmail)
      return NextResponse.json({ message: "No OTP generated for this email" }, { status: 400 })
    }

    if (record.otp !== Number.parseInt(otp)) {
      console.log("OTP mismatch:", { provided: otp, expected: record.otp })
      return NextResponse.json({ message: "Invalid OTP" }, { status: 400 })
    }

    if (new Date() > record.expires) {
      console.log("OTP expired for:", normalizedEmail)
      return NextResponse.json({ message: "OTP expired" }, { status: 400 })
    }

    // Check if email already exists
    const existingUser = await User.findOne({
      email: { $regex: new RegExp("^" + normalizedEmail + "$", "i") },
    })

    if (existingUser) {
      console.log(`Registration failed: Email already exists - ${normalizedEmail}`)
      return NextResponse.json({ message: "Email already registered" }, { status: 400 })
    }

    // Create new user
    const hashedPassword = await bcrypt.hash(password, 10)
    const user = new User({
      username,
      email: normalizedEmail,
      password: hashedPassword,
      dob,
      number,
      language,
      preferences: Array.isArray(preferences) ? preferences : [preferences],
    })

    await user.save()
    console.log(`User registered successfully: ${normalizedEmail}, ID: ${user._id}`)

    // Clear OTP after successful registration
    delete otpStore[normalizedEmail]

    return NextResponse.json({ success: true })
  } catch (err) {
    console.error("Registration error:", err)
    return NextResponse.json(
      { message: "Registration failed", error: err instanceof Error ? err.message : String(err) },
      { status: 500 },
    )
  }
}
