import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'
import './assets/css/style.css'
import './index.css'
import { App } from './App.tsx'
import { ErrorBoundary } from './components/ErrorBoundary.tsx'

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <BrowserRouter>
      <ErrorBoundary fallbackTitle="Sherlock AI Platform Initialization Error">
        <App />
      </ErrorBoundary>
    </BrowserRouter>
  </StrictMode>,
)
