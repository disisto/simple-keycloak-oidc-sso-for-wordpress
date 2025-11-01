/**
 *    Simple OIDC SSO
 *    Version 1.0.0
 *
 *    A lightweight WordPress plugin for quick and easy OpenID Connect authentication.
 *    Designed specifically for Keycloak identity provider.
 *    Simple setup, automatic user sync, and secure token handling.
 *
 *    Documentation: https://github.com/disisto/simple-keycloak-oidc-sso-for-wordpress
 *
 *
 *    Licensed under GPL v2 or later (https://www.gnu.org/licenses/gpl-2.0.html)
 *
 *    Copyright (c) 2025 Roberto Di Sisto
 *
 *    This program is free software; you can redistribute it and/or modify
 *    it under the terms of the GNU General Public License as published by
 *    the Free Software Foundation; either version 2 of the License, or
 *    (at your option) any later version.
 *
 *    This program is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *    GNU General Public License for more details.
 **/

/**
 * Login Page JavaScript
 * CSP-compliant external script
 */

(function() {
    'use strict';

    /**
     * Add OIDC-only mode class to body if configured
     */
    function initOidcOnlyMode() {
        if (window.simpleOidcConfig && window.simpleOidcConfig.oidcOnly) {
            document.body.classList.add('oidc-only-mode');
        }
    }

    /**
     * Move SSO button above login form (between logo and form)
     */
    function repositionSsoButton() {
        var ssoWrapper = document.getElementById('oidc-sso-wrapper');
        var separator = document.querySelector('.oidc-separator');
        var loginForm = document.getElementById('loginform');

        if (ssoWrapper && loginForm && loginForm.parentNode) {
            // Insert SSO wrapper before login form
            loginForm.parentNode.insertBefore(ssoWrapper, loginForm);

            // Insert separator before login form (after SSO wrapper)
            if (separator) {
                loginForm.parentNode.insertBefore(separator, loginForm);
            }
        }
    }

    /**
     * Initialize on DOM ready
     */
    function init() {
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', function() {
                initOidcOnlyMode();
                repositionSsoButton();
            });
        } else {
            initOidcOnlyMode();
            repositionSsoButton();
        }
    }

    init();
})();
