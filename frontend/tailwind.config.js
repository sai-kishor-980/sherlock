/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: "class",
  theme: {
    extend: {
      colors: {
        dark: {
          950: "#060911",
          900: "#090d16",
          850: "#0d131f",
          800: "#131b2c",
          750: "#182236",
          700: "#1e293b",
          600: "#334155",
        },
        forensic: {
          cyan: "#06b6d4",
          emerald: "#10b981",
          amber: "#f59e0b",
          rose: "#f43f5e",
          indigo: "#6366f1",
          violet: "#8b5cf6",
          blue: "#3b82f6",
        }
      },
      fontFamily: {
        sans: ["Plus Jakarta Sans", "Inter", "sans-serif"],
        display: ["Outfit", "Plus Jakarta Sans", "sans-serif"],
        mono: ["JetBrains Mono", "Fira Code", "monospace"],
      }
    },
  },
  plugins: [],
}
