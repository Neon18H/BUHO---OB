(function(){
  const root = document.documentElement;
  const stored = localStorage.getItem('buho-auth-theme') || 'dark';
  root.setAttribute('data-theme', stored);
  window.toggleTheme = function(){
    const next = root.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
    root.setAttribute('data-theme', next);
    localStorage.setItem('buho-auth-theme', next);
  };
})();
