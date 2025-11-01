<?php
/**
 * Plugin Name: Simple OIDC SSO
 * Description: Lightweight OpenID Connect SSO plugin for Keycloak
 * Version: 1.0.0
 * Requires at least: 5.3
 * Requires PHP: 7.4
 * Author: Roberto Di Sisto
 * Author URI: https://disisto.de
 * License: GPL v2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: simple-oidc-sso
 */

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

if (!defined('ABSPATH')) {
    exit;
}

// Plugin constants
define('SOIDC_VERSION', '1.0.0');
define('SOIDC_DIR', plugin_dir_path(__FILE__));
define('SOIDC_URL', plugin_dir_url(__FILE__));

// Load plugin class
require_once SOIDC_DIR . 'includes/class-simple-oidc.php';

// Initialize plugin
function simple_oidc_init() {
    $instance = Simple_OIDC::get_instance();

    // Initialize Network Admin for Multisite
    if (is_multisite() && is_network_admin()) {
        require_once SOIDC_DIR . 'admin/class-network-admin.php';
        new Simple_OIDC_Network_Admin();
    }

    return $instance;
}
add_action('plugins_loaded', 'simple_oidc_init');

// Activation hook
register_activation_hook(__FILE__, 'simple_oidc_activate');
function simple_oidc_activate($network_wide) {
    $default_options = array(
        'enabled' => '0',
        'logout_from_idp' => '0',
        'oidc_only' => '0',
        'auto_create_users' => '1',
        'button_text' => '',
        'picture_claim' => '',
        'server_url' => '',
        'realm' => '',
        'client_id' => '',
        'client_secret' => '',
    );

    if (is_multisite() && $network_wide) {
        // Network activation - set up network options
        add_site_option('simple_oidc_network_options', array_merge($default_options, array(
            'add_users_to_all_sites' => '0',
        )));

        // Initialize each existing site
        $sites = get_sites(array('number' => 1000));
        foreach ($sites as $site) {
            switch_to_blog($site->blog_id);
            add_option('simple_oidc_options', $default_options);
            restore_current_blog();
        }
    } else {
        // Single site activation
        add_option('simple_oidc_options', $default_options);
    }
}

// Deactivation hook
register_deactivation_hook(__FILE__, 'simple_oidc_deactivate');
function simple_oidc_deactivate($network_wide) {
    if (is_multisite() && $network_wide) {
        // Network deactivation - clean up all sites
        $sites = get_sites(array('number' => 1000));
        foreach ($sites as $site) {
            switch_to_blog($site->blog_id);
            global $wpdb;
            $wpdb->query("DELETE FROM {$wpdb->options} WHERE option_name LIKE '_transient_simple_oidc_%'");
            restore_current_blog();
        }
    } else {
        // Single site deactivation
        global $wpdb;
        $wpdb->query("DELETE FROM {$wpdb->options} WHERE option_name LIKE '_transient_simple_oidc_%'");
    }
}

// When a new site is created in multisite, initialize it (only register on actual multisite)
if (is_multisite()) {
    add_action('wp_initialize_site', 'simple_oidc_new_site', 10, 2);
}

function simple_oidc_new_site($new_site, $args) {
    // Double-check we're on multisite
    if (!is_multisite()) {
        return;
    }

    if (is_plugin_active_for_network(plugin_basename(__FILE__))) {
        switch_to_blog($new_site->blog_id);

        // Check if network options exist
        $network_options = get_site_option('simple_oidc_network_options', array());

        // Initialize site with network options as default
        if (!empty($network_options)) {
            // Remove multisite-specific options
            unset($network_options['add_users_to_all_sites']);
            add_option('simple_oidc_options', $network_options);
        } else {
            // Fallback to default options
            add_option('simple_oidc_options', array(
                'enabled' => '0',
                'logout_from_idp' => '0',
                'oidc_only' => '0',
                'auto_create_users' => '1',
                'button_text' => '',
                'picture_claim' => '',
                'server_url' => '',
                'realm' => '',
                'client_id' => '',
                'client_secret' => '',
            ));
        }

        restore_current_blog();
    }
}

// Add Settings link on plugins page
add_filter('plugin_action_links_' . plugin_basename(__FILE__), function($links) {
    $settings_link = '<a href="' . admin_url('admin.php?page=simple-oidc-sso') . '">' . __('Settings', 'simple-oidc-sso') . '</a>';
    array_unshift($links, $settings_link);
    return $links;
});
