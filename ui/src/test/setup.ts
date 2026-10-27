// SPDX-License-Identifier: MIT

// Loaded before every suite (vitest.config.ts setupFiles).

// jest-dom's DOM matchers are the assertion register for this suite: toBeDisabled()
// fails with the element's markup, where a hand-rolled truthiness check fails with
// "expected false to be true" and no clue which element was wrong.
import '@testing-library/jest-dom/vitest'

import { cleanup } from '@testing-library/react'
import { afterEach, beforeEach, vi } from 'vitest'

// Unmount between tests. Every suite shares one jsdom document, so a component left
// mounted keeps its timers and listeners running through the next test's assertions.
afterEach(cleanup)

// Node 25 and later define a localStorage global of their own, undefined unless node was
// started with --localstorage-file, and the test environment leaves it shadowing jsdom's.
// A dashboard tested against that is tested against a browser that refuses all storage.
// Before each test because unstubGlobals puts the shadow back after every one.
beforeEach(() => {
  if (window.localStorage !== undefined) return
  const dom = (globalThis as { jsdom?: { window: { localStorage: Storage } } }).jsdom
  if (dom === undefined) {
    throw new Error('the test environment has no localStorage and no jsdom to take one from')
  }
  vi.stubGlobal('localStorage', dom.window.localStorage)
})
