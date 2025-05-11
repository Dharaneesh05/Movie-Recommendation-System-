import { NextResponse } from "next/server"
import nodemailer from "nodemailer"
import dbConnect from "@/lib/mongodb"
import User from "@/models/User"
import { otpStore } from "../generate-otp/route"

export async function POST(request: Request) {
  try {
    await dbConnect()

    const { email } = await request.json()
    const normalizedEmail = email.toLowerCase()

    if (!normalizedEmail || !normalizedEmail.includes("@")) {
      console.log("Invalid email for password reset:", email)
      return NextResponse.json({ message: "Invalid email" }, { status: 400 })
    }

    const user = await User.findOne({
      email: { $regex: new RegExp("^" + normalizedEmail + "$", "i") },
    })

    if (!user) {
      console.log("User not found for password reset:", normalizedEmail)
      return NextResponse.json({ message: "Invalid email or password" }, { status: 404 })
    }

    const otp = Math.floor(1000 + Math.random() * 9000)
    const expires = new Date(Date.now() + 10 * 60 * 1000) // 10 minutes
    otpStore[normalizedEmail] = { otp, expires, type: "password-reset" }

    // Setup Nodemailer transporter
    const transporter = nodemailer.createTransport({
      host: "smtp.gmail.com",
      port: 587,
      secure: false,
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
    })

    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: normalizedEmail,
      subject: "Password Reset OTP for CINEFELLAS",
      text: `Your OTP for password reset is: ${otp}. It expires in 10 minutes.`,
    })

    console.log(`Password reset OTP sent to ${normalizedEmail}: ${otp}`)

    return NextResponse.json({ message: "Password reset OTP sent" })
  } catch (err) {
    console.error("Email sending error:", err)
    return NextResponse.json(
      { message: "Failed to send OTP", error: err instanceof Error ? err.message : String(err) },
      { status: 500 },
    )
  }
}
