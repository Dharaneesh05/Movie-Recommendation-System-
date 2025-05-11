"use client"

import { useState } from "react"
import { useRouter } from "next/navigation"

export default function LoginPage() {
  const router = useRouter()
  const [email, setEmail] = useState("")
  const [password, setPassword] = useState("")
  const [showPassword, setShowPassword] = useState(false)
  const [loading, setLoading] = useState(false)

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!email) {
      alert("Please enter an email address.")
      return
    }
    if (!password) {
      alert("Please enter a password.")
      return
    }

    setLoading(true)
    try {
      const res = await fetch("/api/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: email.toLowerCase(), password }),
      })
      const data = await res.json()

      if (res.ok && data.success && data.token) {
        localStorage.setItem("token", data.token)
        alert("Login successful!")
        router.push("/homepage")
      } else {
        const errorMessage = data.message || "Invalid email or password"
        alert(`Login failed: ${errorMessage}. Please check your email or register if you haven't.`)
      }
    } catch (error) {
      alert("Cannot connect to the server. Please ensure the server is running and try again.")
    } finally {
      setLoading(false)
    }
  }

  const handleForgotPassword = async () => {
    const emailInput = prompt("Enter your email address:")
    if (!emailInput) {
      alert("Email is required for password reset.")
      return
    }
    try {
      const res = await fetch("/api/request-password-reset", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: emailInput.toLowerCase() }),
      })
      const data = await res.json()
      if (res.ok) {
        const otp = prompt("Enter the OTP sent to your email:")
        if (!otp) {
          alert("OTP is required.")
          return
        }
        const newPassword = prompt("Enter your new password:")
        if (!newPassword) {
          alert("New password is required.")
          return
        }
        const resetRes = await fetch("/api/reset-password", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ email: emailInput.toLowerCase(), otp, newPassword }),
        })
        const resetData = await resetRes.json()
        if (resetRes.ok) {
          alert("Password reset successful. Please log in with your new password.")
        } else {
          alert(`Password reset failed: ${resetData.message || "Unknown error"}`)
        }
      } else {
        alert(`Failed to send OTP: ${data.message || "Unknown error"}`)
      }
    } catch (error) {
      alert("Cannot connect to the server. Please ensure the server is running and try again.")
    }
  }

  return (
    <div
      className="min-h-screen flex flex-col items-center justify-center bg-gray-900 text-white px-4 py-8"
      style={{ backgroundImage: "url('/images/cinema-background.jpg')", backgroundSize: 'cover', backgroundPosition: 'center' }}
    >
      <div className="site-title-container mb-6 w-full max-w-md flex justify-center">
        <div className="site-title text-5xl font-extrabold tracking-widest text-yellow-400 select-none text-center">
          CINEfellas
        </div>
      </div>

      <div className="w-full max-w-md bg-black bg-opacity-90 p-6 rounded-xl shadow-2xl mx-auto transition-transform duration-300 hover:scale-105 hover:shadow-3xl">
        <h2 className="text-center text-3xl font-bold mb-6 tracking-wide">Sign In</h2>
        <form onSubmit={handleLogin} className="space-y-3">
          <div>
            <label htmlFor="email" className="block mb-1 font-semibold">
              Email
            </label>
            <input
              type="email"
              id="email"
              className="w-full p-2 rounded bg-gray-800 text-white focus:outline-none focus:ring-4 focus:ring-yellow-400 transition"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
              disabled={loading}
            />
          </div>

          <div>
            <label htmlFor="password" className="block mb-1 font-semibold">
              Password
            </label>
            <div className="relative">
              <input
                type={showPassword ? "text" : "password"}
                id="password"
                className="w-full p-2 rounded bg-gray-800 text-white focus:outline-none focus:ring-4 focus:ring-yellow-400 transition"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                disabled={loading}
              />
              <button
                type="button"
                onClick={() => setShowPassword(!showPassword)}
                className="absolute right-2 top-2 text-yellow-400 focus:outline-none"
                aria-label={showPassword ? "Hide password" : "Show password"}
              >
                {showPassword ? (
                  <svg
                    xmlns="http://www.w3.org/2000/svg"
                    className="h-5 w-5"
                    fill="none"
                    viewBox="0 0 24 24"
                    stroke="currentColor"
                  >
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13.875 18.825A10.05 10.05 0 0112 19c-5.523 0-10-4.477-10-10a9.96 9.96 0 012.175-6.125M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 3l18 18" />
                  </svg>
                ) : (
                  <svg
                    xmlns="http://www.w3.org/2000/svg"
                    className="h-5 w-5"
                    fill="none"
                    viewBox="0 0 24 24"
                    stroke="currentColor"
                  >
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M2.458 12C3.732 7.943 7.523 5 12 5c4.477 0 8.268 2.943 9.542 7-1.274 4.057-5.065 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
                  </svg>
                )}
              </button>
            </div>
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full bg-yellow-500 hover:bg-yellow-600 text-black font-bold py-3 rounded transition-colors"
          >
            {loading ? "Signing In..." : "Sign In"}
          </button>
        </form>

        <div className="text-center mt-6 space-y-2 text-white">
          <p>
            Don't have an account?{" "}
            <a href="/register" className="text-yellow-400 hover:underline">
              Register here
            </a>
          </p>
          <p>
            <button
              onClick={handleForgotPassword}
              className="text-yellow-400 hover:underline focus:outline-none"
            >
              Forgot Password?
            </button>
          </p>
        </div>
      </div>
    </div>
  )
}
