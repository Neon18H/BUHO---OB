import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App';
import './styles/noc.css';

const root = document.getElementById('app-root');
if (root) {
  const page = root.dataset.page || 'overview';
  ReactDOM.createRoot(root).render(
    <React.StrictMode>
      <App page={page} />
    </React.StrictMode>
  );
}
