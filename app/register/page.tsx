"use client"

import { useState } from "react"
import { useRouter } from "next/navigation"

export default function RegisterPage() {
  const router = useRouter()
  const [username, setUsername] = useState("")
  const [email, setEmail] = useState("")
  const [password, setPassword] = useState("")
  const [showPassword, setShowPassword] = useState(false)
  const [otp, setOtp] = useState("")
  const [dob, setDob] = useState("")
  const [number, setNumber] = useState("")
  const [language, setLanguage] = useState("")
  const [preferences, setPreferences] = useState("")
  const [loading, setLoading] = useState(false)

  const handleGenerateOtp = async () => {
    if (!email) {
      alert("Please enter an email address")
      return
    }
    try {
      const res = await fetch("/api/generate-otp", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email }),
      })
      const data = await res.json()
      if (res.ok) {
        alert(data.message || "OTP sent to your email")
      } else {
        alert(data.message || "Failed to generate OTP")
      }
    } catch (err) {
      alert("Error connecting to server. Please try again.")
    }
  }

  const handleRegister = async (e: React.FormEvent) => {
    e.preventDefault()
    setLoading(true)
    const body = {
      username,
      email: email.toLowerCase(),
      password,
      dob,
      number,
      language,
      preferences: [preferences],
      otp,
    }
    try {
      const res = await fetch("/api/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      })
      const data = await res.json()
      if (data.success) {
        localStorage.setItem("language", language)
        localStorage.setItem("preferences", JSON.stringify([preferences]))
        alert("Registration successful! Please log in.")
        router.push("/login")
      } else {
        alert(data.message || "Registration failed")
      }
    } catch (err) {
      alert("Error connecting to server. Please try again.")
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen flex flex-col items-center justify-center bg-gray-900 text-white px-4 py-8" style={{ backgroundImage: "url('/images/cinema-background.jpg')", backgroundSize: 'cover', backgroundPosition: 'center' }}>
      <div className="site-title-container mb-6 w-full max-w-md flex justify-center">
        <div className="site-title text-5xl font-extrabold tracking-widest text-yellow-400 select-none text-center">
          CINEfellas
        </div>
      </div>

      <div className="w-full max-w-md bg-black bg-opacity-90 p-6 rounded-xl shadow-2xl mx-auto transition-transform duration-300 hover:scale-105 hover:shadow-3xl">
        <h2 className="text-center text-3xl font-bold mb-6 tracking-wide">Sign Up</h2>
        <form onSubmit={handleRegister} className="space-y-3">
          <div>
            <label htmlFor="username" className="block mb-1 font-semibold">
              Username
            </label>
            <input
              type="text"
              id="username"
              className="w-full p-2 rounded bg-gray-800 text-white focus:outline-none focus:ring-4 focus:ring-yellow-400 transition"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              required
              disabled={loading}
            />
          </div>

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

          <div>
            <label htmlFor="dob" className="block mb-1 font-semibold">
              Date of Birth
            </label>
            <input
              type="date"
              id="dob"
              className="w-full p-2 rounded bg-gray-800 text-white focus:outline-none focus:ring-4 focus:ring-yellow-400 transition"
              value={dob}
              onChange={(e) => setDob(e.target.value)}
              required
              disabled={loading}
            />
          </div>

          <div>
            <label htmlFor="number" className="block mb-1 font-semibold">
              Mobile Number
            </label>
            <input
              type="number"
              id="number"
              maxLength={10}
              onInput={(e) => {
                const target = e.target as HTMLInputElement
                target.value = target.value.slice(0, 10)
              }}
              className="w-full p-2 rounded bg-gray-800 text-white focus:outline-none focus:ring-4 focus:ring-yellow-400 transition"
              value={number}
              onChange={(e) => setNumber(e.target.value)}
              required
              disabled={loading}
            />
          </div>

          <div>
            <label htmlFor="language" className="block mb-1 font-semibold">
              Preferred Language
            </label>
            <select
              id="language"
              className="w-full p-2 rounded bg-gray-800 text-white focus:outline-none focus:ring-4 focus:ring-yellow-400 transition"
              value={language}
              onChange={(e) => setLanguage(e.target.value)}
              required
              disabled={loading}
            >
              <option value="">Select your preferred</option>
              <option value="tamil">Tamil</option>
              <option value="english">English</option>
              <option value="hindi">Hindi</option>
              <option value="telegu">Telegu</option>
              <option value="malayalam">Malayalam</option>
              <option value="kannada">Kannada</option>
            </select>
          </div>

          <div>
            <label htmlFor="preferences" className="block mb-1 font-semibold">
              Preferences
            </label>
            <select
              id="preferences"
              className="w-full p-2 rounded bg-gray-800 text-white focus:outline-none focus:ring-4 focus:ring-yellow-400 transition"
              value={preferences}
              onChange={(e) => setPreferences(e.target.value)}
              required
              disabled={loading}
            >
              <option value="">Select your favorite genres</option>
              <option value="action">Action</option>
              <option value="thriller">Thriller</option>
              <option value="fantasy">Fantasy</option>
              <option value="comedy">Comedy</option>
              <option value="drama">Drama</option>
              <option value="horror">Horror</option>
              <option value="romance">Romance</option>
            </select>
          </div>

          <div className="flex items-center space-x-4 mt-4">
            <button
              type="button"
              onClick={handleGenerateOtp}
              disabled={loading}
              className="bg-yellow-500 hover:bg-yellow-600 text-black font-bold py-2 px-4 rounded transition-colors"
            >
              Generate OTP
            </button>
            <input
              type="text"
              id="otp"
              placeholder="Enter OTP"
              className="flex-grow p-2 rounded bg-gray-700 text-white focus:outline-none focus:ring-4 focus:ring-yellow-400 transition"
              value={otp}
              onChange={(e) => setOtp(e.target.value)}
              required
              disabled={loading}
            />
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full bg-yellow-500 hover:bg-yellow-600 text-black font-bold py-3 rounded mt-6 transition-colors"
          >
            {loading ? "Registering..." : "Register"}
          </button>
        </form>

        <div className="text-center mt-6 space-y-2 text-white">
          <p>
            Already have an account?{" "}
            <a href="/login" className="text-yellow-400 hover:underline">
              Sign In
            </a>
          </p>
        </div>
      </div>
    </div>
  )
}
