"use client"

import { useEffect, useRef } from "react"

export default function SiteTitle() {
  const titleRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    const titleElement = titleRef.current
    if (!titleElement) return

    const spans = titleElement.querySelectorAll("span")

    spans.forEach((span, index) => {
      span.style.animationDelay = `${index * 0.1}s`
    })
  }, [])

  return (
    <div className="site-title-container absolute top-4 left-1/2 transform -translate-x-1/2 flex justify-center items-center mb-4">
      <div
        ref={titleRef}
        className="site-title font-serif text-5xl font-bold text-white tracking-wider flex relative"
        style={{ textShadow: "2px 2px 4px rgba(0, 0, 0, 0.3)" }}
      >
        <span className="inline-block origin-center animate-wave">C</span>
        <span className="inline-block origin-center animate-wave">I</span>
        <span className="inline-block origin-center animate-wave">N</span>
        <span className="inline-block origin-center animate-wave">E</span>
        <span className="inline-block origin-center animate-wave">f</span>
        <span className="inline-block origin-center animate-wave">e</span>
        <span className="inline-block origin-center animate-wave">l</span>
        <span className="inline-block origin-center animate-wave">l</span>
        <span className="inline-block origin-center animate-wave">a</span>
        <span className="inline-block origin-center animate-wave">s</span>
      </div>
    </div>
  )
}
