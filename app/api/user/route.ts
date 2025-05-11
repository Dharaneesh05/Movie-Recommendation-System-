import { NextResponse } from "next/server"
import jwt from "jsonwebtoken"
import dbConnect from "@/lib/mongodb"
import User from "@/models/User"

export async function GET(request: Request) {
  try {
    await dbConnect()

    // Get the authorization header
    const authHeader = request.headers.get("authorization")
    const token = authHeader && authHeader.split(" ")[1]

    if (!token) {
      return NextResponse.json({ success: false, message: "No token provided" }, { status: 401 })
    }

    if (!process.env.JWT_SECRET) {
      console.error("JWT_SECRET not set during user fetch")
      return NextResponse.json({ success: false, message: "Server configuration error" }, { status: 500 })
    }

    // Verify the token
    const decoded = jwt.verify(token, process.env.JWT_SECRET) as { userId: string }

    // Find the user
    const user = await User.findById(decoded.userId).select("username preferences language")

    if (!user) {
      console.log("User not found for fetch:", decoded.userId)
      return NextResponse.json({ success: false, message: "User not found" }, { status: 404 })
    }

    return NextResponse.json({ success: true, user })
  } catch (err) {
    console.error("User fetch error:", err)
    return NextResponse.json(
      { success: false, message: "Server error", error: err instanceof Error ? err.message : String(err) },
      { status: 500 },
    )
  }
}
