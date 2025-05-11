import { NextResponse } from "next/server"
import bcrypt from "bcryptjs"
import dbConnect from "@/lib/mongodb"
import User from "@/models/User"
import { otpStore } from "../generate-otp/route"

export async function POST(request: Request) {
  try {
    await dbConnect()

    const { email, otp, newPassword } = await request.json()
    const normalizedEmail = email.toLowerCase()

    const record = otpStore[normalizedEmail]

    if (
      !record ||
      record.otp !== Number.parseInt(otp) ||
      new Date() > record.expires ||
      record.type !== "password-reset"
    ) {
      console.log("Invalid or expired OTP for password reset:", { email: normalizedEmail, providedOtp: otp })
      return NextResponse.json({ message: "Invalid or expired OTP" }, { status: 400 })
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10)

    await User.updateOne(
      { email: { $regex: new RegExp("^" + normalizedEmail + "$", "i") } },
      { $set: { password: hashedPassword } },
    )

    console.log(`Password reset for: ${normalizedEmail}`)

    // Clear OTP after successful password reset
    delete otpStore[normalizedEmail]

    return NextResponse.json({ success: true, message: "Password reset successful" })
  } catch (err) {
    console.error("Password reset error:", err)
    return NextResponse.json(
      { message: "Password reset failed", error: err instanceof Error ? err.message : String(err) },
      { status: 500 },
    )
  }
}
