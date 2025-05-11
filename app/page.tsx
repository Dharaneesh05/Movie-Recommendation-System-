"use client"

import type React from "react"

import { useState } from "react"
import Link from "next/link"
import { useRouter } from "next/navigation"
import SiteTitle from "@/components/SiteTitle"

export default function RegisterPage() {
  const router = useRouter()
  const [formData, setFormData] = useState({
    username: "",
    email: "",
    password: "",
    otp: "",
    dob: "",
    number: "",
    language: "",
    preferences: "",
  })
  const [showPassword, setShowPassword] = useState(false)
  const [isLoading, setIsLoading] = useState(false)

  const handleChange = (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>) => {
    setFormData({ ...formData, [e.target.id]: e.target.value })
  }

  const generateOtp = async () => {
    if (!formData.email) {
      alert("Please enter an email address")
      return
    }

    setIsLoading(true)
    try {
      const res = await fetch("/api/generate-otp", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: formData.email }),
      })
      const data = await res.json()
      if (res.ok) {
        alert(data.message || "OTP sent to your email")
      } else {
        alert(data.message || "Failed to generate OTP")
      }
    } catch (err) {
      alert("Error connecting to server. Please try again.")
    } finally {
      setIsLoading(false)
    }
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setIsLoading(true)

    try {
      const body = {
        username: formData.username,
        email: formData.email.toLowerCase(),
        password: formData.password,
        dob: formData.dob,
        number: formData.number,
        language: formData.language,
        preferences: [formData.preferences], // Store as array
        otp: formData.otp,
      }

      const res = await fetch("/api/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      })
      const data = await res.json()

      if (data.success) {
        // Store language and preferences in localStorage
        localStorage.setItem("language", body.language)
        localStorage.setItem("preferences", JSON.stringify(body.preferences))
        alert("Registration successful! Please log in.")
        router.push("/login")
      } else {
        alert(data.message || "Registration failed")
      }
    } catch (err) {
      alert("Error connecting to server. Please try again.")
    } finally {
      setIsLoading(false)
    }
  }

  return (
    <div
      className="min-h-screen flex flex-col items-center justify-center bg-cover bg-center"
      style={{ backgroundImage: "url('/images/cinema-background.jpg')" }}
    >
      <SiteTitle />

      <div className="container shadow-lg max-w-md w-full bg-black/80 p-6 rounded-lg transition-transform hover:scale-102 hover:shadow-yellow-500/80">
        <h2 className="text-center mb-3 text-white text-2xl font-bold">Sign Up</h2>

        <form id="registrationForm" onSubmit={handleSubmit}>
          <table className="w-full">
            <tbody>
              <tr>
                <td>
                  <label htmlFor="username" className="form-label text-white">
                    Username
                  </label>
                </td>
                <td>
                  <input
                    type="text"
                    id="username"
                    className="form-control w-full p-2 rounded bg-gray-800 text-white border border-gray-700"
                    required
                    value={formData.username}
                    onChange={handleChange}
                  />
                </td>
              </tr>
              <tr>
                <td>
                  <label htmlFor="email" className="form-label text-white">
                    Email
                  </label>
                </td>
                <td>
                  <input
                    type="email"
                    id="email"
                    className="form-control w-full p-2 rounded bg-gray-800 text-white border border-gray-700"
                    required
                    value={formData.email}
                    onChange={handleChange}
                  />
                </td>
              </tr>
              <tr>
                <td>
                  <label htmlFor="password" className="form-label text-white">
                    Password
                  </label>
                </td>
                <td>
                  <div className="relative">
                    <input
                      type={showPassword ? "text" : "password"}
                      id="password"
                      className="form-control w-full p-2 rounded bg-gray-800 text-white border border-gray-700"
                      required
                      value={formData.password}
                      onChange={handleChange}
                    />
                    <button
                      type="button"
                      className="absolute inset-y-0 right-0 pr-3 flex items-center"
                      onClick={() => setShowPassword(!showPassword)}
                    >
                      {showPassword ? (
                        <svg
                          xmlns="http://www.w3.org/2000/svg"
                          className="h-5 w-5 text-gray-400"
                          viewBox="0 0 20 20"
                          fill="currentColor"
                        >
                          <path d="M10 12a2 2 0 100-4 2 2 0 000 4z" />
                          <path
                            fillRule="evenodd"
                            d="M.458 10C1.732 5.943 5.522 3 10 3s8.268 2.943 9.542 7c-1.274 4.057-5.064 7-9.542 7S1.732 14.057.458 10zM14 10a4 4 0 11-8 0 4 4 0 018 0z"
                            clipRule="evenodd"
                          />
                        </svg>
                      ) : (
                        <svg
                          xmlns="http://www.w3.org/2000/svg"
                          className="h-5 w-5 text-gray-400"
                          viewBox="0 0 20 20"
                          fill="currentColor"
                        >
                          <path
                            fillRule="evenodd"
                            d="M3.707 2.293a1 1 0 00-1.414 1.414l14 14a1 1 0 001.414-1.414l-1.473-1.473A10.014 10.014 0 0019.542 10C18.268 5.943 14.478 3 10 3a9.958 9.958 0 00-4.512 1.074l-1.78-1.781zm4.261 4.26l1.514 1.515a2.003 2.003 0 012.45 2.45l1.514 1.514a4 4 0 00-5.478-5.478z"
                            clipRule="evenodd"
                          />
                          <path d="M12.454 16.697L9.75 13.992a4 4 0 01-3.742-3.741L2.335 6.578A9.98 9.98 0 00.458 10c1.274 4.057 5.065 7 9.542 7 .847 0 1.669-.105 2.454-.303z" />
                        </svg>
                      )}
                    </button>
                  </div>
                </td>
              </tr>
              <tr>
                <td>
                  <button
                    type="button"
                    id="generateOtp"
                    className="bg-yellow-500 text-black font-bold p-2 rounded w-full hover:bg-yellow-600"
                    onClick={generateOtp}
                    disabled={isLoading}
                  >
                    Generate OTP
                  </button>
                </td>
                <td>
                  <input
                    type="text"
                    id="otp"
                    className="form-control w-full p-2 rounded bg-gray-800 text-white border border-gray-700"
                    placeholder="Enter OTP"
                    required
                    value={formData.otp}
                    onChange={handleChange}
                  />
                </td>
              </tr>
              <tr>
                <td>
                  <label htmlFor="dob" className="form-label text-white">
                    Date of Birth
                  </label>
                </td>
                <td>
                  <input
                    type="date"
                    id="dob"
                    className="form-control w-full p-2 rounded bg-gray-800 text-white border border-gray-700"
                    required
                    value={formData.dob}
                    onChange={handleChange}
                  />
                </td>
              </tr>
              <tr>
                <td>
                  <label htmlFor="number" className="form-label text-white">
                    Mobile Number
                  </label>
                </td>
                <td>
                  <input
                    type="number"
                    id="number"
                    className="form-control w-full p-2 rounded bg-gray-800 text-white border border-gray-700"
                    required
                    maxLength={10}
                    value={formData.number}
                    onChange={(e) => {
                      if (e.target.value.length <= 10) {
                        handleChange(e)
                      }
                    }}
                  />
                </td>
              </tr>
              <tr>
                <td>
                  <label htmlFor="language" className="form-label text-white">
                    Preferred Language
                  </label>
                </td>
                <td>
                  <select
                    id="language"
                    className="form-select w-full p-2 rounded bg-gray-800 text-white border border-gray-700"
                    required
                    value={formData.language}
                    onChange={handleChange}
                  >
                    <option value="">Select your preferred</option>
                    <option value="Tamil">Tamil</option>
                    <option value="English">English</option>
                    <option value="Hindi">Hindi</option>
                    <option value="Telugu">Telugu</option>
                    <option value="Malayalam">Malayalam</option>
                    <option value="Kannada">Kannada</option>
                  </select>
                </td>
              </tr>
              <tr>
                <td>
                  <label htmlFor="preferences" className="form-label text-white">
                    Preferences
                  </label>
                </td>
                <td>
                  <select
                    id="preferences"
                    className="form-select w-full p-2 rounded bg-gray-800 text-white border border-gray-700"
                    required
                    value={formData.preferences}
                    onChange={handleChange}
                  >
                    <option value="">Select your favorite genres</option>
                    <option value="Action">Action</option>
                    <option value="Thriller">Thriller</option>
                    <option value="Fantasy">Fantasy</option>
                    <option value="Comedy">Comedy</option>
                    <option value="Drama">Drama</option>
                    <option value="Horror">Horror</option>
                    <option value="Romance">Romance</option>
                  </select>
                </td>
              </tr>
            </tbody>
          </table>
          <br />
          <button
            type="submit"
            id="register"
            className="bg-yellow-500 text-black font-bold p-3 rounded w-full hover:bg-yellow-600 transition-colors"
            disabled={isLoading}
          >
            {isLoading ? "Registering..." : "Register"}
          </button>
        </form>

        <div className="mt-4 text-center text-white">
          <p>
            Already have an account?{" "}
            <Link href="/login" className="text-yellow-500 hover:underline">
              Sign In
            </Link>
          </p>
        </div>
      </div>
    </div>
  )
}
