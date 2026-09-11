import React, { useState, useEffect } from 'react';
import GraphView from './components/GraphView.jsx';

export default function App() {
  const [isConsole, setIsConsole] = useState(() => {
    const params = new URLSearchParams(window.location.search);
    const hash = window.location.hash;
    const path = window.location.pathname;
    return params.get('console') === 'true' || hash === '#console' || path.startsWith('/console');
  });

  useEffect(() => {
    const checkRoute = () => {
      const params = new URLSearchParams(window.location.search);
      const hash = window.location.hash;
      const path = window.location.pathname;
      const active = params.get('console') === 'true' || hash === '#console' || path.startsWith('/console');
      setIsConsole(active);

      if (!active && (path === '/' || path === '/index.html')) {
        window.location.replace('/landing-page/index.html');
      }
    };

    checkRoute();
    window.addEventListener('popstate', checkRoute);
    window.addEventListener('hashchange', checkRoute);
    return () => {
      window.removeEventListener('popstate', checkRoute);
      window.removeEventListener('hashchange', checkRoute);
    };
  }, []);

  if (!isConsole) {
    return null;
  }

  return <GraphView />;
}

