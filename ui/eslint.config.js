// SPDX-License-Identifier: MIT

import js from '@eslint/js'
import jsxA11y from 'eslint-plugin-jsx-a11y'
import reactHooks from 'eslint-plugin-react-hooks'
import tseslint from 'typescript-eslint'

export default tseslint.config(
  { ignores: ['dist/**', 'node_modules/**', 'src/generated/**'] },
  js.configs.recommended,
  // Type-checked rules are the reason this config exists: no-floating-promises and
  // no-misused-promises catch dropped async work in event handlers, which is the
  // failure mode a dashboard that polls and mutates is most exposed to. They are
  // scoped to the sources tsconfig covers -- this config file is not one of them.
  ...tseslint.configs.recommendedTypeChecked.map((c) => ({ ...c, files: ['**/*.{ts,tsx}'] })),
  {
    files: ['**/*.{ts,tsx}'],
    languageOptions: {
      parserOptions: {
        projectService: true,
        tsconfigRootDir: import.meta.dirname,
      },
    },
    plugins: {
      'react-hooks': reactHooks,
      'jsx-a11y': jsxA11y,
    },
    rules: {
      ...reactHooks.configs.recommended.rules,
      ...jsxA11y.flatConfigs.recommended.rules,
    },
  },
  {
    // Tests replace globals and assert on deliberately wrong shapes, so the rules
    // that exist to catch accidental `any` in product code only generate noise here.
    files: ['**/*.test.{ts,tsx}', 'src/test/**'],
    rules: {
      '@typescript-eslint/no-unsafe-assignment': 'off',
      '@typescript-eslint/no-unsafe-argument': 'off',
      '@typescript-eslint/no-unsafe-member-access': 'off',
      // Destructuring the queries off a render result is the Testing Library idiom,
      // and they are declared as interface methods purely so they read as such.
      // None of them touch `this`.
      '@typescript-eslint/unbound-method': 'off',
    },
  },
)
