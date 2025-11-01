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
 * Admin Page JavaScript
 * CSP-compliant external script
 */

(function() {
    'use strict';

    /**
     * Toggle collapsible sections
     * @param {string} id - Section identifier
     */
    window.toggleOIDCSection = function(id) {
        var body = document.getElementById(id + '-body');
        var toggle = document.getElementById(id + '-toggle');
        if (body && toggle) {
            body.classList.toggle('open');
            toggle.classList.toggle('open');
        }
    };

    /**
     * Copy debug information to clipboard
     */
    function copyDebugInfo() {
        var debugText = document.getElementById('debug-info-text');
        if (!debugText) {
            return;
        }

        var temp = document.createElement('textarea');
        temp.value = debugText.value;
        temp.style.position = 'fixed';
        temp.style.opacity = '0';
        document.body.appendChild(temp);
        temp.select();

        try {
            document.execCommand('copy');
            alert('Debug information copied to clipboard!');
        } catch (err) {
            console.error('Failed to copy debug info:', err);
            alert('Failed to copy to clipboard. Please try again.');
        }

        document.body.removeChild(temp);
    }

    /**
     * Download debug information as text file
     */
    function downloadDebugInfo() {
        var debugText = document.getElementById('debug-info-text');
        if (!debugText) {
            return;
        }

        var debugContent = debugText.value;
        var blob = new Blob([debugContent], { type: 'text/plain' });
        var url = window.URL.createObjectURL(blob);
        var a = document.createElement('a');
        a.href = url;
        a.download = 'simple-oidc-debug-info-' + Date.now() + '.txt';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        window.URL.revokeObjectURL(url);
    }

    /**
     * Setup event listeners for debug info buttons
     */
    function setupDebugInfoButtons() {
        var copyButton = document.getElementById('copy-debug-info');
        var downloadButton = document.getElementById('download-debug-info');

        if (copyButton) {
            copyButton.addEventListener('click', copyDebugInfo);
        }

        if (downloadButton) {
            downloadButton.addEventListener('click', downloadDebugInfo);
        }
    }

    /**
     * Setup event listeners for dismiss buttons
     */
    function setupDismissButtons() {
        var dismissButtons = document.querySelectorAll('[data-dismiss]');
        dismissButtons.forEach(function(button) {
            button.addEventListener('click', function() {
                var target = this.closest('.oidc-card');
                if (target) {
                    target.style.display = 'none';
                }
            });
        });
    }

    /**
     * Setup event listeners for collapsible sections
     */
    function setupCollapsibleSections() {
        var collapsibleHeaders = document.querySelectorAll('.oidc-collapsible-header');
        collapsibleHeaders.forEach(function(header) {
            header.addEventListener('click', function() {
                var sectionId = this.getAttribute('data-section-id');
                if (sectionId) {
                    window.toggleOIDCSection(sectionId);
                }
            });
        });
    }

    /**
     * Initialize on DOM ready
     */
    function init() {
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', function() {
                setupDismissButtons();
                setupCollapsibleSections();
                setupDebugInfoButtons();
            });
        } else {
            setupDismissButtons();
            setupCollapsibleSections();
            setupDebugInfoButtons();
        }
    }

    init();
})();
