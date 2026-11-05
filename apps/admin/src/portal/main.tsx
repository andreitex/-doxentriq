import React from 'react';
import { createRoot } from 'react-dom/client';
import Portal from './Portal';
import Invitation from './Invitation';
import './portal.css';

createRoot(document.getElementById('root')!).render(<React.StrictMode>{window.location.pathname === '/invite' ? <Invitation /> : <Portal />}</React.StrictMode>);
