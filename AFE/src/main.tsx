import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import App from './App.tsx'

// 过滤由浏览器扩展引起的无关报错（扩展消息通道在异步响应前关闭），避免干扰控制台
const EXTENSION_MESSAGE_ERROR =
  'A listener indicated an asynchronous response by returning true, but the message channel closed before a response was received';
window.addEventListener('unhandledrejection', (event) => {
  const msg = event.reason?.message ?? String(event.reason);
  if (typeof msg === 'string' && msg.includes(EXTENSION_MESSAGE_ERROR)) {
    event.preventDefault();
    event.stopPropagation();
  }
});

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>,
)
