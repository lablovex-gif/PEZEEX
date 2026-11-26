import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import App from './App.tsx';
import './index.css';
import { registerWebMcpTools } from './lib/webmcp';

// Register WebMCP tools immediately on page load for in-browser AI agents
registerWebMcpTools();

try {
  const links = document.querySelectorAll("link[rel*='icon']");
  links.forEach((l) => {
    const link = l as HTMLLinkElement;
    if (link.href && !link.href.includes('?v=')) {
      link.href = link.href + '?v=3';
    }
  });
} catch (_) {}

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);

if ('serviceWorker' in navigator && (import.meta as any).env?.PROD) {
  window.addEventListener('load', () => {
    navigator.serviceWorker.register('/sw.js').catch(() => {});
  });
}
