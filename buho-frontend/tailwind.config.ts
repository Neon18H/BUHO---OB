import type { Config } from 'tailwindcss';

const config: Config = {
  darkMode: ['class'],
  content: ['./app/**/*.{ts,tsx}', './components/**/*.{ts,tsx}', './lib/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        background: '#05080f',
        card: '#0a1220',
        border: '#1e293b',
        accent: '#22d3ee',
        success: '#22c55e',
        danger: '#ef4444'
      },
      backgroundImage: {
        'noc-grid': 'linear-gradient(rgba(34, 211, 238, 0.05) 1px, transparent 1px), linear-gradient(90deg, rgba(34, 211, 238, 0.05) 1px, transparent 1px)'
      },
      animation: {
        sweep: 'sweep 2s linear infinite'
      },
      keyframes: {
        sweep: {
          '0%': { transform: 'translateX(-100%)' },
          '100%': { transform: 'translateX(200%)' }
        }
      }
    }
  },
  plugins: [],
};

export default config;
