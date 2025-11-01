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
 * Admin Settings Class
 */
class Simple_OIDC_Admin {

    public function __construct() {
        add_action('admin_menu', array($this, 'add_menu'));
        add_action('admin_init', array($this, 'handle_post_requests'));
        add_action('admin_enqueue_scripts', array($this, 'enqueue_admin_styles'));
    }

    public function add_menu() {
        add_options_page(
            'OIDC SSO Settings',
            'OIDC SSO',
            'manage_options',
            'simple-oidc-sso',
            array($this, 'settings_page')
        );
    }

    public function enqueue_admin_styles($hook) {
        if ($hook !== 'settings_page_simple-oidc-sso') {
            return;
        }

        wp_enqueue_style('dashicons');

        // Enqueue CSS
        wp_enqueue_style(
            'simple-oidc-admin',
            SOIDC_URL . 'assets/css/admin.css',
            array('dashicons'),
            SOIDC_VERSION
        );

        // Enqueue JavaScript
        wp_enqueue_script(
            'simple-oidc-admin',
            SOIDC_URL . 'assets/js/admin.js',
            array(),
            SOIDC_VERSION,
            true
        );
    }

    /**
     * Handle POST requests early to allow redirects
     */
    public function handle_post_requests() {
        // Only on our settings page
        if (!isset($_GET['page']) || $_GET['page'] !== 'simple-oidc-sso') {
            return;
        }

        if (!current_user_can('manage_options')) {
            return;
        }

        // Handle test connection
        if (isset($_POST['simple_oidc_test'])) {
            check_admin_referer('simple_oidc_test', '_wpnonce_test');
            $result = $this->test_connection();
            set_transient('simple_oidc_test_result', json_encode($result), 60);
            // Store last test result for debug info (no expiration)
            set_transient('simple_oidc_last_test_result', json_encode($result), 0);
            wp_safe_redirect(admin_url('admin.php?page=simple-oidc-sso&tested=1'));
            exit;
        }

        // Handle save
        if (isset($_POST['simple_oidc_save'])) {
            check_admin_referer('simple_oidc_settings', '_wpnonce_settings');
            $old_options = get_option('simple_oidc_options', array());

            // Build new options array
            $new_options = array(
                'enabled' => (isset($_POST['enabled']) && $_POST['enabled'] === '1') ? '1' : '0',
                'logout_from_idp' => (isset($_POST['logout_from_idp']) && $_POST['logout_from_idp'] === '1') ? '1' : '0',
                'oidc_only' => (isset($_POST['oidc_only']) && $_POST['oidc_only'] === '1') ? '1' : '0',
                'auto_create_users' => (isset($_POST['auto_create_users']) && $_POST['auto_create_users'] === '1') ? '1' : '0',
                'button_text' => isset($_POST['button_text']) ? sanitize_text_field(wp_unslash($_POST['button_text'])) : '',
                'picture_claim' => isset($_POST['picture_claim']) ? sanitize_text_field(wp_unslash($_POST['picture_claim'])) : '',
                'server_url' => isset($_POST['server_url']) ? esc_url_raw(trim(wp_unslash($_POST['server_url']))) : '',
                'realm' => isset($_POST['realm']) ? sanitize_text_field(wp_unslash($_POST['realm'])) : '',
                'client_id' => isset($_POST['client_id']) ? sanitize_text_field(wp_unslash($_POST['client_id'])) : '',
                'client_secret' => !empty($_POST['client_secret']) ? wp_unslash($_POST['client_secret']) : (isset($old_options['client_secret']) ? $old_options['client_secret'] : ''),
            );

            // Validate required fields before enabling critical modes
            $validation_errors = array();

            if ($new_options['enabled'] === '1' || $new_options['oidc_only'] === '1') {
                if (empty($new_options['server_url'])) {
                    $validation_errors[] = 'OIDC Server URL is required';
                }
                if (empty($new_options['realm'])) {
                    $validation_errors[] = 'Realm is required';
                }
                if (empty($new_options['client_id'])) {
                    $validation_errors[] = 'Client ID is required';
                }
                if (empty($new_options['client_secret'])) {
                    $validation_errors[] = 'Client Secret is required';
                }
            }

            if (!empty($validation_errors)) {
                // Disable critical modes if validation fails
                $new_options['enabled'] = '0';
                $new_options['oidc_only'] = '0';

                set_transient('simple_oidc_validation_errors', $validation_errors, 60);
                update_option('simple_oidc_options', $new_options);
                wp_safe_redirect(admin_url('admin.php?page=simple-oidc-sso&validation_error=1'));
                exit;
            }

            update_option('simple_oidc_options', $new_options);
            set_transient('simple_oidc_save_message', 'Settings saved successfully!', 60);
            wp_safe_redirect(admin_url('admin.php?page=simple-oidc-sso&saved=1'));
            exit;
        }
    }

    public function test_connection() {
        $options = get_option('simple_oidc_options', array());
        $results = array();

        // Step 0: System requirements check
        global $wp_version;
        $php_version = phpversion();
        $required_php = '7.4';
        $required_wp = '5.3';

        if (version_compare($php_version, $required_php, '>=')) {
            $results[] = array('status' => 'success', 'requirement' => 'PHP Version', 'expected' => $required_php . '+', 'actual' => $php_version);
        } else {
            $results[] = array('status' => 'error', 'requirement' => 'PHP Version', 'expected' => $required_php . '+', 'actual' => $php_version);
            return array('success' => false, 'message' => 'System requirements not met', 'details' => $results);
        }

        if (version_compare($wp_version, $required_wp, '>=')) {
            $results[] = array('status' => 'success', 'requirement' => 'WordPress Version', 'expected' => $required_wp . '+', 'actual' => $wp_version);
        } else {
            $results[] = array('status' => 'error', 'requirement' => 'WordPress Version', 'expected' => $required_wp . '+', 'actual' => $wp_version);
            return array('success' => false, 'message' => 'System requirements not met', 'details' => $results);
        }

        // Check required PHP extensions
        $required_extensions = array('curl', 'json', 'openssl', 'mbstring');
        foreach ($required_extensions as $ext) {
            if (extension_loaded($ext)) {
                // Get extension version
                $version = 'Loaded';
                if ($ext === 'curl') {
                    $curl_info = curl_version();
                    $version = isset($curl_info['version']) ? $curl_info['version'] : 'Loaded';
                } elseif ($ext === 'openssl') {
                    $version = defined('OPENSSL_VERSION_TEXT') ? OPENSSL_VERSION_TEXT : 'Loaded';
                } elseif ($ext === 'json') {
                    $version = 'Built-in';
                } elseif ($ext === 'mbstring') {
                    $version = 'Loaded';
                }
                $results[] = array('status' => 'success', 'requirement' => 'PHP Extension: ' . $ext, 'expected' => 'Loaded', 'actual' => $version);
            } else {
                $results[] = array('status' => 'error', 'requirement' => 'PHP Extension: ' . $ext, 'expected' => 'Loaded', 'actual' => 'Missing');
                return array('success' => false, 'message' => 'Required PHP extension missing', 'details' => $results);
            }
        }

        // Step 1: Validate configuration
        if (empty($options['server_url'])) {
            $results[] = array('status' => 'error', 'requirement' => 'Server URL', 'expected' => 'Configured', 'actual' => 'Missing');
            return array('success' => false, 'message' => 'Configuration incomplete', 'details' => $results);
        }
        if (empty($options['realm'])) {
            $results[] = array('status' => 'error', 'requirement' => 'Realm', 'expected' => 'Configured', 'actual' => 'Missing');
            return array('success' => false, 'message' => 'Configuration incomplete', 'details' => $results);
        }
        if (empty($options['client_id'])) {
            $results[] = array('status' => 'error', 'requirement' => 'Client ID', 'expected' => 'Configured', 'actual' => 'Missing');
            return array('success' => false, 'message' => 'Configuration incomplete', 'details' => $results);
        }

        $results[] = array('status' => 'success', 'requirement' => 'Configuration', 'expected' => 'Valid', 'actual' => 'Valid');

        // Step 2: Test Realm accessibility
        $realm_url = rtrim($options['server_url'], '/') . '/realms/' . $options['realm'];
        $response = wp_remote_get($realm_url, array('timeout' => 10, 'sslverify' => true));

        if (is_wp_error($response)) {
            $results[] = array('status' => 'error', 'requirement' => 'Realm Accessibility', 'expected' => 'HTTP 200', 'actual' => 'Error: ' . $response->get_error_message());
            return array('success' => false, 'message' => 'Cannot reach OIDC server', 'details' => $results);
        }

        $code = wp_remote_retrieve_response_code($response);
        if ($code !== 200) {
            $results[] = array('status' => 'error', 'requirement' => 'Realm Accessibility', 'expected' => 'HTTP 200', 'actual' => 'HTTP ' . $code);
            return array('success' => false, 'message' => 'Realm not accessible', 'details' => $results);
        }

        $results[] = array('status' => 'success', 'requirement' => 'Realm Accessibility', 'expected' => 'HTTP 200', 'actual' => 'HTTP 200');

        // Step 3: Test OIDC Well-Known Configuration
        $wellknown_url = rtrim($options['server_url'], '/') . '/realms/' . $options['realm'] . '/.well-known/openid-configuration';
        $response = wp_remote_get($wellknown_url, array('timeout' => 10, 'sslverify' => true));

        if (is_wp_error($response)) {
            $results[] = array('status' => 'error', 'requirement' => 'OIDC Discovery', 'expected' => 'Accessible', 'actual' => 'Error: ' . $response->get_error_message());
            return array('success' => false, 'message' => 'OIDC configuration not accessible', 'details' => $results);
        }

        $body = wp_remote_retrieve_body($response);
        $oidc_config = json_decode($body, true);

        if (empty($oidc_config) || !isset($oidc_config['authorization_endpoint'])) {
            $results[] = array('status' => 'error', 'requirement' => 'OIDC Discovery', 'expected' => 'Valid JSON', 'actual' => 'Invalid/Empty');
            return array('success' => false, 'message' => 'Invalid OIDC configuration', 'details' => $results);
        }

        $results[] = array('status' => 'success', 'requirement' => 'OIDC Discovery', 'expected' => 'Valid', 'actual' => 'Valid');

        // Step 4: Validate required endpoints
        $required_endpoints = array(
            'authorization_endpoint' => 'Authorization Endpoint',
            'token_endpoint' => 'Token Endpoint',
            'userinfo_endpoint' => 'UserInfo Endpoint',
            'end_session_endpoint' => 'End Session Endpoint'
        );
        $all_endpoints_present = true;

        foreach ($required_endpoints as $endpoint => $label) {
            if (isset($oidc_config[$endpoint])) {
                // Show full URL with scheme and domain
                $url = $oidc_config[$endpoint];
                $results[] = array('status' => 'success', 'requirement' => $label, 'expected' => 'Configured', 'actual' => $url);
            } else {
                $results[] = array('status' => 'warning', 'requirement' => $label, 'expected' => 'Configured', 'actual' => 'Missing');
                $all_endpoints_present = false;
            }
        }

        // Step 5: Validate issuer
        if (isset($oidc_config['issuer'])) {
            $expected_issuer = rtrim($options['server_url'], '/') . '/realms/' . $options['realm'];
            if ($oidc_config['issuer'] === $expected_issuer) {
                $results[] = array('status' => 'success', 'requirement' => 'Issuer', 'expected' => $expected_issuer, 'actual' => $oidc_config['issuer']);
            } else {
                $results[] = array('status' => 'warning', 'requirement' => 'Issuer', 'expected' => $expected_issuer, 'actual' => $oidc_config['issuer']);
            }
        }

        // Step 6: Check supported scopes
        if (isset($oidc_config['scopes_supported']) && is_array($oidc_config['scopes_supported'])) {
            $required_scopes = array('openid', 'email', 'profile');
            $missing_scopes = array_diff($required_scopes, $oidc_config['scopes_supported']);

            // Show all supported scopes
            $all_scopes = implode(', ', $oidc_config['scopes_supported']);

            if (empty($missing_scopes)) {
                $results[] = array('status' => 'success', 'requirement' => 'Required Scopes', 'expected' => 'openid, email, profile', 'actual' => $all_scopes);
            } else {
                $results[] = array('status' => 'warning', 'requirement' => 'Required Scopes', 'expected' => 'openid, email, profile', 'actual' => 'Missing: ' . implode(', ', $missing_scopes));
            }
        } else {
            $results[] = array('status' => 'warning', 'requirement' => 'Required Scopes', 'expected' => 'openid, email, profile', 'actual' => 'Not Available');
        }

        return array(
            'success' => $all_endpoints_present,
            'message' => $all_endpoints_present ? 'All tests passed successfully!' : 'Tests completed with warnings',
            'details' => $results
        );
    }

    public function get_debug_info() {
        global $wp_version, $wpdb;

        $debug_info = array();

        // WordPress Environment
        $debug_info['WordPress'] = array(
            'Version' => $wp_version,
            'Site URL' => get_site_url(),
            'Home URL' => get_home_url(),
            'Multisite' => is_multisite() ? 'Yes' : 'No',
            'Debug Mode' => defined('WP_DEBUG') && WP_DEBUG ? 'Enabled' : 'Disabled',
            'Memory Limit' => WP_MEMORY_LIMIT,
            'Max Upload Size' => size_format(wp_max_upload_size()),
            'Timezone' => wp_timezone_string(),
            'Language' => get_locale(),
        );

        // Server Environment
        $debug_info['Server'] = array(
            'PHP Version' => phpversion(),
            'Server Software' => isset($_SERVER['SERVER_SOFTWARE']) ? sanitize_text_field(wp_unslash($_SERVER['SERVER_SOFTWARE'])) : 'Unknown',
            'MySQL Version' => $wpdb->db_version(),
            'HTTPS' => is_ssl() ? 'Enabled' : 'Disabled',
            'User Agent' => isset($_SERVER['HTTP_USER_AGENT']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT'])) : 'Unknown',
        );

        // PHP Extensions
        $required_extensions = array('curl', 'json', 'openssl', 'mbstring');
        $extensions_status = array();
        foreach ($required_extensions as $ext) {
            if (extension_loaded($ext)) {
                $version = 'Loaded';
                if ($ext === 'curl') {
                    $curl_info = curl_version();
                    $version = isset($curl_info['version']) ? $curl_info['version'] : 'Loaded';
                } elseif ($ext === 'openssl') {
                    $version = defined('OPENSSL_VERSION_TEXT') ? OPENSSL_VERSION_TEXT : 'Loaded';
                } elseif ($ext === 'json') {
                    $version = 'Built-in (PHP ' . PHP_VERSION . ')';
                } elseif ($ext === 'mbstring') {
                    $version = 'Loaded';
                    if (function_exists('mb_get_info')) {
                        $mb_info = mb_get_info();
                        if (isset($mb_info['mbstring_version'])) {
                            $version = $mb_info['mbstring_version'];
                        }
                    }
                }
                $extensions_status[$ext] = $version;
            } else {
                $extensions_status[$ext] = 'Missing';
            }
        }
        $debug_info['PHP Extensions'] = $extensions_status;

        // Plugin Configuration (sanitized)
        $options = get_option('simple_oidc_options', array());
        $debug_info['Plugin Settings'] = array(
            'Plugin Version' => SOIDC_VERSION,
            'Plugin Enabled' => isset($options['enabled']) && $options['enabled'] === '1' ? 'Yes' : 'No',
            'OIDC Only Mode' => isset($options['oidc_only']) && $options['oidc_only'] === '1' ? 'Yes' : 'No',
            'Auto Create Users' => isset($options['auto_create_users']) && $options['auto_create_users'] === '1' ? 'Yes' : 'No',
            'Logout from Keycloak' => isset($options['logout_from_idp']) && $options['logout_from_idp'] === '1' ? 'Yes' : 'No',
            'Server URL' => !empty($options['server_url']) ? 'Set' : 'Not Set',
            'Realm' => !empty($options['realm']) ? 'Set' : 'Not Set',
            'Client ID' => !empty($options['client_id']) ? 'Set' : 'Not Set',
            'Client Secret' => !empty($options['client_secret']) ? 'Set' : 'Not Set',
            'Button Text' => !empty($options['button_text']) ? $options['button_text'] : 'Default',
            'Picture Claim' => !empty($options['picture_claim']) ? $options['picture_claim'] : 'Default (picture)',
        );

        // Add Connection Test status
        $test_result_json = get_transient('simple_oidc_last_test_result');
        if ($test_result_json) {
            $test_result = json_decode($test_result_json, true);
            $debug_info['Plugin Settings']['Last Connection Test'] = isset($test_result['success']) && $test_result['success'] ? 'Successful' : 'Failed';
        } else {
            $debug_info['Plugin Settings']['Last Connection Test'] = 'Not Tested';
        }

        // Multisite Info (if applicable)
        if (is_multisite()) {
            $network_options = get_site_option('simple_oidc_network_options', array());
            $debug_info['Multisite Settings'] = array(
                'Network Enabled' => isset($network_options['enabled']) && $network_options['enabled'] === '1' ? 'Yes' : 'No',
                'Add Users to All Sites' => isset($network_options['add_users_to_all_sites']) && $network_options['add_users_to_all_sites'] === '1' ? 'Yes' : 'No',
                'Total Sites' => get_blog_count(),
                'Current Site ID' => get_current_blog_id(),
            );
        }

        // Active Plugins
        $active_plugins = get_option('active_plugins', array());
        $plugin_list = array();
        foreach ($active_plugins as $plugin) {
            $plugin_data = get_plugin_data(WP_PLUGIN_DIR . '/' . $plugin, false, false);
            $plugin_list[] = $plugin_data['Name'] . ' ' . $plugin_data['Version'];
        }
        $debug_info['Active Plugins'] = $plugin_list;

        // WordPress Site Health (if available)
        if (class_exists('WP_Site_Health')) {
            $site_health = WP_Site_Health::get_instance();
            $health_check_site_status = get_option('health-check-site-status', array());

            if (!empty($health_check_site_status)) {
                $debug_info['Site Health'] = array(
                    'Status' => isset($health_check_site_status['good']) ? 'Good: ' . $health_check_site_status['good'] : 'Unknown',
                    'Recommended Improvements' => isset($health_check_site_status['recommended']) ? $health_check_site_status['recommended'] : 0,
                    'Critical Issues' => isset($health_check_site_status['critical']) ? $health_check_site_status['critical'] : 0,
                );
            }
        }

        return $debug_info;
    }

    public function export_debug_info_text() {
        $debug_info = $this->get_debug_info();
        $output = "=== Simple OIDC SSO - Debug Information ===\n";
        $output .= "Generated: " . current_time('mysql') . "\n";
        $output .= "Site: " . get_site_url() . "\n";
        $output .= str_repeat('=', 50) . "\n\n";

        foreach ($debug_info as $section => $data) {
            $output .= "[$section]\n";
            $output .= str_repeat('-', 50) . "\n";

            if (is_array($data)) {
                if (isset($data[0])) {
                    // Indexed array (like plugins list)
                    foreach ($data as $item) {
                        $output .= "  - " . $item . "\n";
                    }
                } else {
                    // Associative array
                    foreach ($data as $key => $value) {
                        $output .= sprintf("%-25s: %s\n", $key, $value);
                    }
                }
            } else {
                $output .= "  " . $data . "\n";
            }
            $output .= "\n";
        }

        return $output;
    }

    public function settings_page() {
        if (!current_user_can('manage_options')) {
            return;
        }

        // Show save message
        $message = '';
        if (isset($_GET['saved']) && $_GET['saved'] === '1') {
            $message = get_transient('simple_oidc_save_message');
            if ($message) {
                delete_transient('simple_oidc_save_message');
            }
        }

        // Show validation errors
        $validation_errors = array();
        if (isset($_GET['validation_error']) && $_GET['validation_error'] === '1') {
            $validation_errors = get_transient('simple_oidc_validation_errors');
            if ($validation_errors) {
                delete_transient('simple_oidc_validation_errors');
            }
        }

        // Show test result
        $test_result = null;
        if (isset($_GET['tested']) && $_GET['tested'] === '1') {
            $result_json = get_transient('simple_oidc_test_result');
            if ($result_json) {
                $test_result = json_decode($result_json, true);
                delete_transient('simple_oidc_test_result');
            }
        }

        // Load current options
        $options = get_option('simple_oidc_options', array(
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

        // Convert to display variables
        $enabled = ($options['enabled'] === '1');
        $logout_from_idp = ($options['logout_from_idp'] === '1');
        $oidc_only = ($options['oidc_only'] === '1');
        $auto_create_users = isset($options['auto_create_users']) ? ($options['auto_create_users'] === '1') : true;
        $button_text = isset($options['button_text']) ? $options['button_text'] : '';
        $picture_claim = isset($options['picture_claim']) ? $options['picture_claim'] : '';
        $server_url = $options['server_url'];
        $realm = $options['realm'];
        $client_id = $options['client_id'];
        $client_secret = $options['client_secret'];

        $is_configured = !empty($server_url) && !empty($realm) && !empty($client_id) && !empty($client_secret);

        ?>
        <div class="wrap">
            <div class="oidc-admin-header">
                <span class="dashicons dashicons-admin-network"></span>
                <div>
                    <h1>OIDC SSO</h1>
                    <p style="margin: 5px 0 0 0; color: #646970;">OpenID Connect authentication for WordPress</p>
                </div>
                <?php if ($is_configured): ?>
                    <div style="margin-left: auto;">
                        <span class="oidc-status-badge <?php echo $enabled ? 'active' : 'inactive'; ?>">
                            <span class="dashicons dashicons-<?php echo $enabled ? 'yes-alt' : 'warning'; ?>"></span>
                            <?php echo $enabled ? 'Active' : 'Inactive'; ?>
                        </span>
                    </div>
                <?php endif; ?>
            </div>

            <?php if ($message): ?>
                <div class="oidc-card" style="border-left: 4px solid #00a32a; background: #f0fdf4;">
                    <div class="oidc-card-header" style="background: #f0fdf4; border-bottom: none; display: flex; justify-content: space-between; align-items: center;">
                        <div style="display: flex; align-items: center; gap: 8px;">
                            <span class="dashicons dashicons-yes-alt" style="color: #00a32a;"></span>
                            <span style="color: #00a32a; font-weight: 600;"><?php echo esc_html($message); ?></span>
                        </div>
                        <button type="button" class="button button-small" data-dismiss="true" style="border: none; background: none; cursor: pointer;">
                            <span class="dashicons dashicons-no-alt" style="margin-top: 3px;"></span>
                        </button>
                    </div>
                </div>
            <?php endif; ?>

            <?php if (!empty($validation_errors)): ?>
                <div class="oidc-card" style="border-left: 4px solid #d63638; background: #fcf0f1;">
                    <div class="oidc-card-header" style="background: #fcf0f1; border-bottom: 1px solid #dba4a6;">
                        <div style="display: flex; align-items: center; gap: 8px;">
                            <span class="dashicons dashicons-warning" style="color: #d63638;"></span>
                            <span style="color: #d63638; font-weight: 600;">Configuration Error</span>
                        </div>
                    </div>
                    <div class="oidc-card-body" style="background: #fcf0f1;">
                        <p style="margin-top: 0;"><strong>Cannot enable plugin or OIDC Only Mode.</strong> The following required fields are missing:</p>
                        <ul style="list-style: disc; margin-left: 20px; margin-bottom: 0;">
                            <?php foreach ($validation_errors as $error): ?>
                                <li><?php echo esc_html($error); ?></li>
                            <?php endforeach; ?>
                        </ul>
                        <p style="margin-bottom: 0;">Please fill in all required fields and save again.</p>
                    </div>
                </div>
            <?php endif; ?>

            <?php if ($test_result): ?>
                <div class="oidc-card" id="test-results-card">
                    <div class="oidc-card-header" style="display: flex; justify-content: space-between; align-items: center;">
                        <div style="display: flex; align-items: center; gap: 8px;">
                            <span class="dashicons dashicons-<?php echo $test_result['success'] ? 'yes-alt' : 'warning'; ?>" style="color: <?php echo $test_result['success'] ? '#00a32a' : '#dba617'; ?>;"></span>
                            <span><?php echo esc_html($test_result['message']); ?></span>
                        </div>
                        <button type="button" class="button button-small" data-dismiss="true">
                            <span class="dashicons dashicons-no-alt" style="margin-top: 3px;"></span>
                            Dismiss
                        </button>
                    </div>
                    <?php if (!empty($test_result['details'])): ?>
                        <div class="oidc-card-body" style="padding: 20px;">
                            <table class="oidc-status-table">
                                <thead>
                                    <tr>
                                        <th>Requirement</th>
                                        <th>Expected</th>
                                        <th>Actual</th>
                                        <th style="text-align: center; width: 80px;">Status</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php foreach ($test_result['details'] as $detail): ?>
                                        <tr>
                                            <td><strong><?php echo esc_html($detail['requirement']); ?></strong></td>
                                            <td><?php echo esc_html($detail['expected']); ?></td>
                                            <td><?php echo esc_html($detail['actual']); ?></td>
                                            <td style="text-align: center;">
                                                <?php
                                                $icon = 'yes';
                                                $class = 'success';
                                                if ($detail['status'] === 'error') {
                                                    $icon = 'dismiss';
                                                    $class = 'error';
                                                }
                                                if ($detail['status'] === 'warning') {
                                                    $icon = 'warning';
                                                    $class = 'warning';
                                                }
                                                ?>
                                                <span class="dashicons dashicons-<?php echo esc_attr($icon); ?> oidc-status-icon <?php echo esc_attr($class); ?>"></span>
                                            </td>
                                        </tr>
                                    <?php endforeach; ?>
                                </tbody>
                            </table>
                        </div>
                    <?php endif; ?>
                </div>
            <?php endif; ?>

            <div class="oidc-card">
                <div class="oidc-card-header">
                    <span class="dashicons dashicons-admin-generic"></span>
                    Configuration
                </div>
                <div class="oidc-card-body">
                    <form method="post" action="">
                        <?php wp_nonce_field('simple_oidc_settings', '_wpnonce_settings'); ?>

                        <table class="form-table" role="presentation">
                            <tr>
                                <th scope="row">
                                    <label for="enabled">Plugin Status</label>
                                </th>
                                <td>
                                    <label>
                                        <input type="checkbox" name="enabled" id="enabled" value="1" <?php echo $enabled ? 'checked="checked"' : ''; ?>>
                                        Enable OIDC authentication
                                    </label>
                                    <?php if ($enabled && !$is_configured): ?>
                                        <p class="description" style="color: #d63638;">
                                            <span class="dashicons dashicons-warning" style="color: #d63638;"></span>
                                            <strong>Warning:</strong> Plugin is enabled but not fully configured!
                                        </p>
                                    <?php endif; ?>
                                </td>
                            </tr>

                            <tr>
                                <th scope="row">
                                    <label for="server_url">OIDC Server URL</label>
                                </th>
                                <td>
                                    <input type="text"
                                           name="server_url"
                                           id="server_url"
                                           value="<?php echo esc_attr($server_url); ?>"
                                           class="regular-text code"
                                           placeholder="https://keycloak.example.com">
                                    <p class="description">Without trailing slash</p>
                                </td>
                            </tr>

                            <tr>
                                <th scope="row">
                                    <label for="realm">Realm</label>
                                </th>
                                <td>
                                    <input type="text"
                                           name="realm"
                                           id="realm"
                                           value="<?php echo esc_attr($realm); ?>"
                                           class="regular-text"
                                           placeholder="myrealm">
                                </td>
                            </tr>

                            <tr>
                                <th scope="row">
                                    <label for="client_id">Client ID</label>
                                </th>
                                <td>
                                    <input type="text"
                                           name="client_id"
                                           id="client_id"
                                           value="<?php echo esc_attr($client_id); ?>"
                                           class="regular-text"
                                           placeholder="wordpress">
                                </td>
                            </tr>

                            <tr>
                                <th scope="row">
                                    <label for="client_secret">Client Secret</label>
                                </th>
                                <td>
                                    <input type="password"
                                           name="client_secret"
                                           id="client_secret"
                                           value="<?php echo esc_attr($client_secret); ?>"
                                           class="regular-text"
                                           autocomplete="off"
                                           placeholder="<?php echo !empty($client_secret) ? '••••••••••••••••' : 'Enter client secret'; ?>">
                                    <p class="description">Leave empty to keep current secret</p>
                                </td>
                            </tr>
                        </table>

                        <h3 style="margin-top: 30px;"><span class="dashicons dashicons-admin-settings"></span> Advanced Options</h3>

                        <table class="form-table" role="presentation">
                            <tr>
                                <th scope="row">
                                    <label for="button_text">Login Button Text</label>
                                </th>
                                <td>
                                    <input type="text"
                                           name="button_text"
                                           id="button_text"
                                           value="<?php echo esc_attr($button_text); ?>"
                                           class="regular-text"
                                           placeholder="Single Sign-On (SSO)">
                                    <p class="description">Text displayed on the OIDC login button</p>
                                </td>
                            </tr>

                            <tr>
                                <th scope="row">
                                    <label for="oidc_only">Login Mode</label>
                                </th>
                                <td>
                                    <label>
                                        <input type="checkbox" name="oidc_only" id="oidc_only" value="1" <?php echo $oidc_only ? 'checked="checked"' : ''; ?>>
                                        OIDC Only Mode (automatic redirect)
                                    </label>
                                    <p class="description">
                                        When enabled, users are automatically redirected to Keycloak when accessing wp-login.php
                                    </p>
                                </td>
                            </tr>

                            <tr>
                                <th scope="row">
                                    <label for="logout_from_idp">Logout Behavior</label>
                                </th>
                                <td>
                                    <label>
                                        <input type="checkbox" name="logout_from_idp" id="logout_from_idp" value="1" <?php echo $logout_from_idp ? 'checked="checked"' : ''; ?>>
                                        Also logout from Keycloak (Single Sign-Out)
                                    </label>
                                    <p class="description">
                                        When enabled, logging out from WordPress will also end the Keycloak session
                                    </p>
                                </td>
                            </tr>

                            <tr>
                                <th scope="row">
                                    <label for="auto_create_users">User Creation</label>
                                </th>
                                <td>
                                    <label>
                                        <input type="checkbox" name="auto_create_users" id="auto_create_users" value="1" <?php echo $auto_create_users ? 'checked="checked"' : ''; ?>>
                                        Automatically create new users
                                    </label>
                                    <p class="description">
                                        When <strong>enabled</strong>: New OIDC users will automatically get a WordPress account.<br>
                                        When <strong>disabled</strong>: Only existing WordPress users can log in via OIDC. New users will be denied access.
                                    </p>
                                </td>
                            </tr>

                            <tr>
                                <th scope="row">
                                    <label for="picture_claim">Profile Picture Claim</label>
                                </th>
                                <td>
                                    <input type="text"
                                           name="picture_claim"
                                           id="picture_claim"
                                           value="<?php echo esc_attr($picture_claim); ?>"
                                           class="regular-text"
                                           placeholder="picture">
                                    <p class="description">Name of the claim containing the profile picture URL (default: picture)</p>
                                </td>
                            </tr>
                        </table>

                        <p class="submit">
                            <button type="submit" name="simple_oidc_save" class="button button-primary button-large">
                                <span class="dashicons dashicons-saved" style="margin-top: 4px;"></span>
                                Save Settings
                            </button>
                        </p>
                    </form>
                </div>
            </div>

            <div class="oidc-card">
                <div class="oidc-card-header">
                    <span class="dashicons dashicons-cloud"></span>
                    Connection Test
                </div>
                <div class="oidc-card-body">
                    <p>Test the connection to your OIDC server and validate the OIDC configuration.</p>
                    <form method="post" action="">
                        <?php wp_nonce_field('simple_oidc_test', '_wpnonce_test'); ?>
                        <p>
                            <button type="submit" name="simple_oidc_test" class="button button-secondary">
                                <span class="dashicons dashicons-update" style="margin-top: 4px;"></span>
                                Run Connection Test
                            </button>
                        </p>
                    </form>
                </div>
            </div>

            <div class="oidc-card">
                <div class="oidc-card-header oidc-collapsible-header" data-section-id="oidc-guide">
                    <div style="display: flex; align-items: center; gap: 8px;">
                        <span class="dashicons dashicons-info"></span>
                        <span>Keycloak Configuration Guide</span>
                    </div>
                    <span class="dashicons dashicons-arrow-down oidc-collapsible-toggle" id="oidc-guide-toggle"></span>
                </div>
                <div class="oidc-card-body oidc-collapsible-body" id="oidc-guide-body">
                    <p style="margin-bottom: 20px;">Follow these steps to configure your Keycloak client for WordPress integration:</p>

                    <h3 style="margin-top: 0;"><span class="dashicons dashicons-admin-generic" style="color: #2271b1;"></span> General Settings</h3>
                    <table class="form-table" style="margin-bottom: 20px;">
                        <tr>
                            <th style="width: 200px;">Client Type</th>
                            <td><strong>OpenID Connect</strong></td>
                        </tr>
                        <tr>
                            <th>Client ID</th>
                            <td><code><?php echo !empty($client_id) ? esc_html($client_id) : 'wordpress'; ?></code></td>
                        </tr>
                    </table>

                    <h3><span class="dashicons dashicons-admin-settings" style="color: #2271b1;"></span> Capability Config</h3>
                    <table class="form-table" style="margin-bottom: 20px;">
                        <tr>
                            <th style="width: 200px;">Client authentication</th>
                            <td><strong style="color: #00a32a;">ON</strong> <span style="color: #646970;">(Required for confidential clients)</span></td>
                        </tr>
                        <tr>
                            <th>Authorization</th>
                            <td><strong style="color: #d63638;">OFF</strong> <span style="color: #646970;">(Not needed for SSO)</span></td>
                        </tr>
                    </table>

                    <h4 style="margin-left: 20px; color: #646970;">Authentication Flow</h4>
                    <table class="form-table" style="margin-bottom: 20px; margin-left: 20px;">
                        <tr>
                            <th style="width: 230px;">Standard flow</th>
                            <td><strong style="color: #00a32a;">ON</strong> <span style="color: #646970;">(Authorization Code Flow)</span></td>
                        </tr>
                        <tr>
                            <th>Direct access grants</th>
                            <td><strong style="color: #d63638;">OFF</strong></td>
                        </tr>
                        <tr>
                            <th>Implicit flow</th>
                            <td><strong style="color: #d63638;">OFF</strong> <span style="color: #646970;">(Deprecated, not secure)</span></td>
                        </tr>
                        <tr>
                            <th>Service accounts roles</th>
                            <td><strong style="color: #d63638;">OFF</strong></td>
                        </tr>
                        <tr>
                            <th>OAuth 2.0 Device Authorization Grant</th>
                            <td><strong style="color: #d63638;">OFF</strong></td>
                        </tr>
                        <tr>
                            <th>OIDC CIBA Grant</th>
                            <td><strong style="color: #d63638;">OFF</strong></td>
                        </tr>
                    </table>

                    <h3><span class="dashicons dashicons-admin-links" style="color: #2271b1;"></span> Login Settings</h3>
                    <div class="keycloak-redirect-uris" style="margin-bottom: 15px;">
                        <table class="form-table">
                            <tr>
                                <th style="width: 250px;">Root URL</th>
                                <td><code><?php echo esc_html(home_url()); ?></code></td>
                            </tr>
                            <tr>
                                <th>Home URL</th>
                                <td><code><?php echo esc_html(home_url()); ?></code></td>
                            </tr>
                            <tr>
                                <th>Valid redirect URIs</th>
                                <td>
                                    <code><?php echo esc_html(wp_login_url()); ?></code><br>
                                    <code><?php echo esc_html(wp_login_url()); ?>?*</code>
                                </td>
                            </tr>
                            <tr>
                                <th>Valid post logout redirect URIs</th>
                                <td>
                                    <code><?php echo esc_html(home_url()); ?></code><br>
                                    <code><?php echo esc_html(home_url()); ?>/*</code>
                                </td>
                            </tr>
                            <tr>
                                <th>Web origins</th>
                                <td><code><?php echo esc_html(home_url()); ?></code></td>
                            </tr>
                        </table>
                    </div>

                    <h3><span class="dashicons dashicons-exit" style="color: #2271b1;"></span> Single Sign-Out Configuration</h3>
                    <p style="margin-bottom: 15px;">To enable Single Sign-Out (SSO) across all applications, configure the following in your Keycloak client:</p>

                    <div style="background: #f6f7f7; border: 1px solid #dcdcde; padding: 15px; border-radius: 4px; margin-bottom: 20px;">
                        <h4 style="margin-top: 0;">Keycloak 26+ Configuration</h4>
                        <p>In your Keycloak client settings, scroll down to the <strong>Logout settings</strong> section. Keycloak supports two logout methods:</p>

                        <div style="background: #d4edda; border-left: 4px solid #00a32a; padding: 12px; margin: 15px 0;">
                            <p style="margin: 0;"><strong>✓ Recommended: Backchannel Logout (Server-to-Server)</strong></p>
                            <p style="margin: 8px 0 0 0; color: #155724;">Most reliable method - no browser dependencies or CSP issues</p>
                        </div>

                        <h4 style="margin-top: 20px;">Option 1: Backchannel Logout (Recommended)</h4>
                        <p style="color: #646970; margin-bottom: 10px;"><strong>Note:</strong> In Keycloak 26, you must turn OFF Front-channel logout to enable Backchannel logout.</p>
                        <ol style="margin-left: 20px;">
                            <li>
                                <strong>Front channel logout:</strong> <strong style="color: #d63638;">OFF</strong>
                                <p style="margin: 8px 0 0 0; color: #646970;">Must be disabled to enable Backchannel logout</p>
                            </li>
                            <li style="margin-top: 12px;">
                                <strong>Backchannel logout URL:</strong><br>
                                <code style="background: white; padding: 4px 8px; border-radius: 3px; margin-top: 4px; display: inline-block;">
                                    <?php echo esc_html(rest_url('simple-oidc/v1/backchannel-logout')); ?>
                                </code>
                                <p style="margin: 8px 0 0 0; color: #646970;">Server-to-server logout notification - instant and reliable</p>
                            </li>
                            <li style="margin-top: 12px;">
                                <strong>Backchannel logout session required:</strong> <strong style="color: #00a32a;">ON</strong>
                                <p style="margin: 8px 0 0 0; color: #646970;">Ensures session information is included in logout requests</p>
                            </li>
                            <li style="margin-top: 12px;">
                                <strong>Backchannel logout revoke offline sessions:</strong> <strong style="color: #00a32a;">ON</strong>
                                <p style="margin: 8px 0 0 0; color: #646970;">Also revokes offline/refresh token sessions</p>
                            </li>
                        </ol>

                        <h4 style="margin-top: 20px;">Option 2: Frontchannel Logout (Alternative)</h4>
                        <p style="color: #646970; margin-bottom: 10px;">Use this if your Keycloak version doesn't support Backchannel logout or if you prefer browser-based logout.</p>
                        <ol style="margin-left: 20px;">
                            <li>
                                <strong>Front channel logout:</strong> <strong style="color: #00a32a;">ON</strong>
                                <p style="margin: 8px 0 0 0; color: #646970;">Enable front-channel logout support</p>
                            </li>
                            <li style="margin-top: 12px;">
                                <strong>Front-channel logout URL:</strong><br>
                                <code style="background: white; padding: 4px 8px; border-radius: 3px; margin-top: 4px; display: inline-block;">
                                    <?php echo esc_html(wp_login_url()); ?>
                                </code>
                                <p style="margin: 8px 0 0 0; color: #646970;">WordPress will be notified via iframe when users logout from other apps</p>
                            </li>
                            <li style="margin-top: 12px;">
                                <strong>Front-channel logout session required:</strong> <strong style="color: #00a32a;">ON</strong>
                                <p style="margin: 8px 0 0 0; color: #646970;">Ensures session information is included in logout requests</p>
                            </li>
                        </ol>

                        <div style="background: #e7f5fe; border-left: 4px solid #2271b1; padding: 12px; margin-top: 15px;">
                            <p style="margin: 0;"><strong>How each method works:</strong></p>
                            <ul style="margin: 8px 0 0 20px;">
                                <li><strong>Backchannel:</strong> OIDC server directly notifies WordPress server when a user logs out from any app (instant, no browser required)</li>
                                <li><strong>Frontchannel:</strong> OIDC server loads a hidden iframe on WordPress login page via user's browser (relies on browser cookies)</li>
                            </ul>
                        </div>
                    </div>

                    <h3><span class="dashicons dashicons-admin-users" style="color: #2271b1;"></span> Profile Picture Setup (Optional)</h3>
                    <p style="margin-bottom: 15px;">To enable profile picture synchronization, you need to configure a mapper in Keycloak:</p>

                    <div style="background: #f6f7f7; border: 1px solid #dcdcde; padding: 15px; border-radius: 4px; margin-bottom: 20px;">
                        <h4 style="margin-top: 0;">Step 1: Navigate to Client Scopes</h4>
                        <ol style="margin-left: 20px;">
                            <li>In Keycloak Admin Console, go to <strong>Client Scopes</strong></li>
                            <li>Click on <strong>profile</strong> scope</li>
                            <li>Go to the <strong>Mappers</strong> tab</li>
                            <li>Click <strong>Add mapper</strong> → <strong>By configuration</strong></li>
                        </ol>

                        <h4>Step 2: Create User Attribute Mapper</h4>
                        <table class="form-table" style="margin-bottom: 15px;">
                            <tr>
                                <th style="width: 200px;">Mapper Type</th>
                                <td><strong>User Attribute</strong></td>
                            </tr>
                            <tr>
                                <th>Name</th>
                                <td><code>picture</code></td>
                            </tr>
                            <tr>
                                <th>User Attribute</th>
                                <td><code>picture</code> <span style="color: #646970;">(or your custom attribute name)</span></td>
                            </tr>
                            <tr>
                                <th>Token Claim Name</th>
                                <td><code><?php echo !empty($picture_claim) ? esc_html($picture_claim) : 'picture'; ?></code></td>
                            </tr>
                            <tr>
                                <th>Claim JSON Type</th>
                                <td><strong>String</strong></td>
                            </tr>
                            <tr>
                                <th>Add to ID token</th>
                                <td><strong style="color: #00a32a;">ON</strong></td>
                            </tr>
                            <tr>
                                <th>Add to access token</th>
                                <td><strong style="color: #00a32a;">ON</strong></td>
                            </tr>
                            <tr>
                                <th>Add to userinfo</th>
                                <td><strong style="color: #00a32a;">ON</strong></td>
                            </tr>
                        </table>

                        <h4>Step 3: Set User Attribute</h4>
                        <p style="margin: 10px 0;">For each user that should have a profile picture:</p>
                        <ol style="margin-left: 20px;">
                            <li>Go to <strong>Users</strong> → Select user → <strong>Attributes</strong> tab</li>
                            <li>Click <strong>Add attribute</strong></li>
                            <li>Key: <code>picture</code></li>
                            <li>Value: <code>https://example.com/path/to/avatar.jpg</code> <span style="color: #646970;">(Full URL to image)</span></li>
                            <li>Click <strong>Save</strong></li>
                        </ol>
                    </div>

                    <div class="oidc-info-box" style="border-left-color: #2271b1; background: #f0f6fc;">
                        <span class="dashicons dashicons-info" style="color: #2271b1;"></span>
                        <strong>Alternative:</strong> You can also use User Property Mapper with <code>picture</code> property if your users already have a picture property in their Keycloak profiles.
                    </div>

                    <div class="oidc-info-box">
                        <span class="dashicons dashicons-warning"></span>
                        <strong>Important:</strong> After configuration, go to the <strong>Credentials</strong> tab and copy the <strong>Client Secret</strong> to the WordPress plugin settings above.
                    </div>
                </div>
            </div>

            <div class="oidc-card">
                <div class="oidc-card-header oidc-collapsible-header" data-section-id="debug-info">
                    <div style="display: flex; align-items: center; gap: 8px;">
                        <span class="dashicons dashicons-admin-tools"></span>
                        <span>System & Debug Information</span>
                    </div>
                    <span class="dashicons dashicons-arrow-down oidc-collapsible-toggle" id="debug-info-toggle"></span>
                </div>
                <div class="oidc-card-body oidc-collapsible-body" id="debug-info-body">
                    <p style="margin-top: 0;">Export system information for troubleshooting. Include this information when reporting issues on GitHub.</p>

                    <div style="background: #f6f7f7; border: 1px solid #c3c4c7; border-radius: 4px; padding: 15px; margin-bottom: 15px; max-height: 400px; overflow-y: auto;">
                        <?php
                        $debug_info = $this->get_debug_info();
                        foreach ($debug_info as $section => $data):
                        ?>
                            <div style="margin-bottom: 15px;">
                                <h4 style="margin: 0 0 8px 0; color: #2271b1;"><?php echo esc_html($section); ?></h4>
                                <div style="padding-left: 15px; font-size: 13px;">
                                    <?php if (is_array($data)): ?>
                                        <?php if (isset($data[0])): ?>
                                            <?php foreach ($data as $item): ?>
                                                <div>• <?php echo esc_html($item); ?></div>
                                            <?php endforeach; ?>
                                        <?php else: ?>
                                            <?php foreach ($data as $key => $value): ?>
                                                <div><strong><?php echo esc_html($key); ?>:</strong> <?php echo esc_html($value); ?></div>
                                            <?php endforeach; ?>
                                        <?php endif; ?>
                                    <?php else: ?>
                                        <div><?php echo esc_html($data); ?></div>
                                    <?php endif; ?>
                                </div>
                            </div>
                        <?php endforeach; ?>
                    </div>

                    <div style="display: flex; gap: 10px;">
                        <button type="button" class="button button-secondary" id="copy-debug-info">
                            <span class="dashicons dashicons-clipboard" style="margin-top: 4px;"></span>
                            Copy to Clipboard
                        </button>
                        <button type="button" class="button button-secondary" id="download-debug-info">
                            <span class="dashicons dashicons-download" style="margin-top: 4px;"></span>
                            Download as Text File
                        </button>
                    </div>

                    <textarea id="debug-info-text" style="display: none;"><?php echo esc_textarea($this->export_debug_info_text()); ?></textarea>
                </div>
            </div>

            <div style="margin-top: 40px; padding: 20px; background: #f9f9f9; border: 1px solid #dcdcde; border-radius: 4px; text-align: center; color: #646970; font-size: 13px;">
                <p style="margin: 0 0 10px 0;">
                    <strong>GitHub Repository:</strong>
                    <a href="https://github.com/disisto/simple-keycloak-oidc-sso-for-wordpress" target="_blank" rel="noopener noreferrer" style="color: #2271b1; text-decoration: none;">
                        https://github.com/disisto/simple-keycloak-oidc-sso-for-wordpress
                    </a>
                </p>
                <p style="margin: 0; line-height: 1.6;">
                    This project is not affiliated with <a href="https://keycloak.org/" target="_blank" rel="noopener noreferrer" style="color: #2271b1;">Keycloak</a> and/or <a href="https://wordpress.org/" target="_blank" rel="noopener noreferrer" style="color: #2271b1;">WordPress</a>.<br>
                    All mentioned trademarks are the property of their respective owners.
                </p>
            </div>
        </div>
        <?php
    }
}
