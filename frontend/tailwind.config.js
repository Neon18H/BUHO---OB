export default {
  content: [
    './src/**/*.{ts,tsx}',
    '../ui/templates/**/*.html',
    '../agents/templates/**/*.html'
  ],
  theme: {
    extend: {
      colors: {
        noc: {
          bg: '#04070f',
          panel: '#0e1526',
          line: '#1d2a46',
          glow: '#38bdf8'
        }
      }
    }
  },
  plugins: []
};
