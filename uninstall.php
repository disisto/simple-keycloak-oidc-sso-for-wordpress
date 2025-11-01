<?php
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
 * Uninstall Script - Removes all plugin data
 */

// If uninstall not called from WordPress, exit
if (!defined('WP_UNINSTALL_PLUGIN')) {
    exit;
}

global $wpdb;

// Robustly check if this is actually multisite AND network activated
$is_multisite = (function_exists('is_multisite') && is_multisite());
$is_network_active = false;

if ($is_multisite) {
    // Check if plugin was network activated
    $network_plugins = get_site_option('active_sitewide_plugins', array());
    $is_network_active = isset($network_plugins[plugin_basename(__FILE__)]);
}

if ($is_multisite && $is_network_active) {
    // Multisite: delete data from all sites
    $sites = get_sites(array('number' => 1000));

    foreach ($sites as $site) {
        switch_to_blog($site->blog_id);

        // Delete site options
        delete_option('simple_oidc_options');

        // Delete site transients
        $wpdb->query("DELETE FROM {$wpdb->options} WHERE option_name LIKE '_transient_simple_oidc_%' OR option_name LIKE '_transient_timeout_simple_oidc_%'");

        // Delete user meta (oidc_id, oidc_avatar, id_token)
        $wpdb->query("DELETE FROM {$wpdb->usermeta} WHERE meta_key IN ('oidc_id', 'oidc_avatar', 'oidc_id_token', 'oidc_session_id', 'oidc_sub')");

        // Delete uploaded avatar images
        $avatars = $wpdb->get_results("SELECT post_id FROM {$wpdb->postmeta} WHERE meta_key = '_wp_attached_file' AND meta_value LIKE 'oidc-avatar-%'");
        foreach ($avatars as $avatar) {
            wp_delete_attachment($avatar->post_id, true);
        }

        restore_current_blog();
    }

    // Delete network options
    delete_site_option('simple_oidc_network_options');

} else {
    // Single site OR multisite site-level activation: delete data
    delete_option('simple_oidc_options');

    // Delete all transients
    $wpdb->query("DELETE FROM {$wpdb->options} WHERE option_name LIKE '_transient_simple_oidc_%' OR option_name LIKE '_transient_timeout_simple_oidc_%'");

    // Delete user meta (oidc_id, oidc_avatar, id_token)
    $wpdb->query("DELETE FROM {$wpdb->usermeta} WHERE meta_key IN ('oidc_id', 'oidc_avatar', 'oidc_id_token', 'oidc_session_id', 'oidc_sub')");

    // Delete uploaded avatar images
    $avatars = $wpdb->get_results("SELECT post_id FROM {$wpdb->postmeta} WHERE meta_key = '_wp_attached_file' AND meta_value LIKE 'oidc-avatar-%'");
    foreach ($avatars as $avatar) {
        wp_delete_attachment($avatar->post_id, true);
    }
}

// Safety cleanup: Remove any leftover network options on single site
if (!$is_multisite) {
    delete_option('simple_oidc_network_options'); // Should not exist on single site

    // Clean up any stray site option entries (belt and suspenders)
    $wpdb->query("DELETE FROM {$wpdb->options} WHERE option_name = 'simple_oidc_network_options'");
}
