// SPDX-License-Identifier: MIT

import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import App from './App'
import { startSession } from './auth'
import { StoreProvider } from './data/StoreProvider'
import './styles.css'

const container = document.getElementById('root')
if (!container) {
  // A missing root means the shipped index.html and this bundle disagree, which is
  // a build failure that must not degrade into a blank page.
  throw new Error('app-tail: index.html is missing its #root element')
}

// The launch token is traded before the first render so no request goes out without the
// session it buys. A failed trade still renders: the app shows the signed-out screen.
void startSession().finally(() => {
  createRoot(container).render(
    <StrictMode>
      <StoreProvider>
        <App />
      </StoreProvider>
    </StrictMode>,
  )
})
