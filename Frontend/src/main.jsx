import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'
import App from './App.jsx'
import ScanGate from './scan/ScanGate.jsx'
import MantineBridge from './theme/MantineBridge.jsx'
import { ThemeProvider } from './theme/ThemeProvider.jsx'
import './styles.css'
import './components/ui.css'

createRoot(document.getElementById('root')).render(
  <StrictMode>
    <ThemeProvider>
      <MantineBridge>
        <ScanGate>
          <BrowserRouter>
            <App />
          </BrowserRouter>
        </ScanGate>
      </MantineBridge>
    </ThemeProvider>
  </StrictMode>,
)
