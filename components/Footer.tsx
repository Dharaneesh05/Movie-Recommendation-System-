export default function Footer() {
  return (
    <div className="footer bg-black py-6 px-4 text-center text-white">
      <p>© {new Date().getFullYear()} Cinefellas. All rights reserved.</p>
      <p>
        <a href="#" className="text-white hover:text-yellow-500 transition-colors">
          Privacy Policy
        </a>{" "}
        |
        <a href="#" className="text-white hover:text-yellow-500 transition-colors ml-2">
          Terms of Service
        </a>
      </p>
    </div>
  )
}
