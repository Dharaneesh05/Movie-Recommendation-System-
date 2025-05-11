import { NextResponse } from "next/server"
import nodemailer from "nodemailer"
import dbConnect from "@/lib/mongodb"

// In-memory OTP store (would use Redis or similar in production)
const otpStore: Record<string, { otp: number; expires: Date }> = {}

export async function POST(request: Request) {
  try {
    await dbConnect()

    const { email } = await request.json()
    const normalizedEmail = email.toLowerCase()

    if (!normalizedEmail || !normalizedEmail.includes("@")) {
      console.log("Invalid email provided for OTP:", email)
      return NextResponse.json({ message: "Invalid email" }, { status: 400 })
    }

    const otp = Math.floor(1000 + Math.random() * 9000)
    const expires = new Date(Date.now() + 10 * 60 * 1000) // 10 minutes
    otpStore[normalizedEmail] = { otp, expires }

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
      subject: "Your OTP for CINEFELLAS Registration",
      text: `Your OTP is: ${otp}. It expires in 10 minutes.`,
    })

    console.log(`OTP sent to ${normalizedEmail}: ${otp}`)
    return NextResponse.json({ message: "OTP sent" })
  } catch (err) {
    console.error("Email sending error:", err)
    return NextResponse.json(
      { message: "Failed to send OTP", error: err instanceof Error ? err.message : String(err) },
      { status: 500 },
    )
  }
}

// Export the OTP store for use in other routes
export { otpStore }
