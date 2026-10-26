// Standalone preview build: the real UI + fake API (no server needed). Build: see docs/ui-preview.html
import { createRoot } from 'react-dom/client'; import { MemoryRouter } from 'react-router-dom'; import './src/styles.css'; import App from './src/App.jsx'; import { AuthProvider } from './src/auth.jsx'; import { ToastProvider } from './src/ui.jsx'; import { installMock } from './src/preview-mock.js'; import data from './test-data/pgdata.json';
installMock(data, { autologin: false });
createRoot(document.getElementById('root')).render(<MemoryRouter initialEntries={['/login']}><ToastProvider><AuthProvider><App /></AuthProvider></ToastProvider></MemoryRouter>);
