import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [
    react(),
    {
      name: 'landing-redirect',
      configureServer(server) {
        server.middlewares.use((req, res, next) => {
          const url = req.url || '';
          // Redirect root visits to landing-page unless console param is explicitly present
          if ((url === '/' || url === '/index.html') && !url.includes('console=true')) {
            res.writeHead(302, { Location: '/landing-page/index.html' });
            res.end();
            return;
          }
          next();
        });
      },
    },
  ],
  server: { port: 5173 },
});

