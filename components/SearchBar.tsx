"use client"

import React from "react"

interface SearchBarProps {
  searchTerm: string
  onSearchChange: (value: string) => void
  language: string
  onLanguageChange: (value: string) => void
  genre: string
  onGenreChange: (value: string) => void
}

const languages = [
  { value: "", label: "All Languages" },
  { value: "tamil", label: "Tamil" },
  { value: "english", label: "English" },
  { value: "hindi", label: "Hindi" },
  { value: "telugu", label: "Telegu" },
  { value: "malayalam", label: "Malayalam" },
  { value: "kannada", label: "Kannada" },
]

const genres = [
  { value: "", label: "All Genres" },
  { value: "action", label: "Action" },
  { value: "thriller", label: "Thriller" },
  { value: "fantasy", label: "Fantasy" },
  { value: "comedy", label: "Comedy" },
  { value: "drama", label: "Drama" },
  { value: "horror", label: "Horror" },
  { value: "romance", label: "Romance" },
]

export default function SearchBar({
  searchTerm,
  onSearchChange,
  language,
  onLanguageChange,
  genre,
  onGenreChange,
}: SearchBarProps) {
  return (
    <div className="mb-6 max-w-4xl mx-auto flex flex-col sm:flex-row items-center space-y-4 sm:space-y-0 sm:space-x-4">
      <div className="relative flex-grow w-full sm:w-auto">
        <svg
          className="absolute left-3 top-1/2 transform -translate-y-1/2 h-5 w-5 text-yellow-400 pointer-events-none"
          xmlns="http://www.w3.org/2000/svg"
          fill="none"
          viewBox="0 0 24 24"
          stroke="currentColor"
          strokeWidth={2}
        >
          <path strokeLinecap="round" strokeLinejoin="round" d="M21 21l-4.35-4.35m0 0A7.5 7.5 0 1110.5 3a7.5 7.5 0 016.15 13.65z" />
        </svg>
        <input
          type="text"
          value={searchTerm}
          onChange={(e) => onSearchChange(e.target.value)}
          placeholder="Search movies..."
          aria-label="Search movies"
          className="w-full pl-10 p-3 rounded-lg bg-gray-800 text-white border border-gray-700 focus:outline-none focus:ring-2 focus:ring-yellow-500 focus:border-yellow-500 shadow-md transition"
        />
      </div>

      <select
        value={language}
        onChange={(e) => onLanguageChange(e.target.value)}
        className="p-3 rounded-lg bg-gray-800 text-white border border-gray-700 focus:outline-none focus:ring-2 focus:ring-yellow-500 transition"
        aria-label="Filter by language"
      >
        {languages.map((lang) => (
          <option key={lang.value} value={lang.value}>
            {lang.label}
          </option>
        ))}
      </select>

      <select
        value={genre}
        onChange={(e) => onGenreChange(e.target.value)}
        className="p-3 rounded-lg bg-gray-800 text-white border border-gray-700 focus:outline-none focus:ring-2 focus:ring-yellow-500 transition"
        aria-label="Filter by genre"
      >
        {genres.map((g) => (
          <option key={g.value} value={g.value}>
            {g.label}
          </option>
        ))}
      </select>
    </div>
  )
}
