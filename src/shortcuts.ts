/**
 * Shortcut API (Syntactic Sugar)
 *
 * 100% delegation - no logic, no state, no conditionals
 * These are purely syntactic sugar for the main API
 */

import type {
  PasskeyNamespace,
  SocialNamespace,
  SignInShortcuts,
  SignUpShortcuts,
} from './types.js';

/**
 * Create shortcut factories
 *
 * Following the implementation principle:
 * - shortcuts.ts にロジックを書かない
 * - 100% 委譲
 * - if / try / state を持たせない
 */
export const createShortcuts = {
  /**
   * Create signIn shortcuts
   */
  signIn(passkey: PasskeyNamespace, social: SocialNamespace): SignInShortcuts {
    return {
      passkey: (opts) => passkey.login(opts),
      social: (provider, opts) => social.loginWithPopup(provider, opts),
    };
  },

  /**
   * Create signUp shortcuts
   */
  signUp(passkey: PasskeyNamespace): SignUpShortcuts {
    return {
      passkey: (opts) => passkey.signUp(opts),
    };
  },
};
