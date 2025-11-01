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
 * Network Admin Settings Class for Multisite
 */
class Simple_OIDC_Network_Admin {

    public function __construct() {
        add_action('network_admin_menu', array($this, 'add_network_menu'));
        add_action('network_admin_edit_simple_oidc_network_save', array($this, 'save_network_settings'));
        add_action('network_admin_edit_simple_oidc_network_test', array($this, 'test_network_connection'));
        add_action('admin_enqueue_scripts', array($this, 'enqueue_admin_styles'));
    }

    public function add_network_menu() {
        add_submenu_page(
            'settings.php',
            'OIDC SSO Network Settings',
            'OIDC SSO',
            'manage_network_options',
            'simple-oidc-network',
            array($this, 'network_settings_page')
        );
    }

    public function enqueue_admin_styles($hook) {
        if ($hook !== 'settings_page_simple-oidc-network') {
            return;
        }

        wp_enqueue_style('dashicons');

        // Use same styles as regular admin
        $custom_css = '
            .oidc-admin-header {
                display: flex;
                align-items: center;
                gap: 15px;
                margin-bottom: 20px;
                padding-bottom: 15px;
                border-bottom: 1px solid #ccd0d4;
            }
            .oidc-admin-header .dashicons {
                font-size: 40px;
                width: 40px;
                height: 40px;
                color: #2271b1;
            }
            .oidc-admin-header h1 {
                margin: 0;
                font-size: 23px;
            }
            .oidc-card {
                background: #fff;
                border: 1px solid #c3c4c7;
                box-shadow: 0 1px 1px rgba(0,0,0,.04);
                margin-bottom: 20px;
            }
            .oidc-card-header {
                background: #f6f7f7;
                border-bottom: 1px solid #c3c4c7;
                padding: 12px 20px;
                font-weight: 600;
                font-size: 14px;
                display: flex;
                align-items: center;
                gap: 8px;
            }
            .oidc-card-header .dashicons {
                color: #2271b1;
            }
            .oidc-card-body {
                padding: 20px;
            }
            .oidc-status-badge {
                display: inline-flex;
                align-items: center;
                gap: 6px;
                padding: 4px 12px;
                border-radius: 3px;
                font-size: 13px;
                font-weight: 500;
            }
            .oidc-status-badge.active {
                background: #00a32a15;
                color: #00a32a;
            }
            .oidc-status-badge.inactive {
                background: #dba61715;
                color: #dba617;
            }
            .oidc-status-badge .dashicons {
                font-size: 16px;
                width: 16px;
                height: 16px;
            }
            .oidc-info-box {
                background: #f0f6fc;
                border-left: 4px solid #2271b1;
                padding: 12px;
                margin: 15px 0;
            }
            .oidc-info-box .dashicons {
                color: #2271b1;
                margin-right: 8px;
            }
            .oidc-status-table {
                width: 100%;
                border-collapse: collapse;
                margin-top: 15px;
            }
            .oidc-status-table th {
                background: #f6f7f7;
                text-align: left;
                padding: 12px;
                font-weight: 600;
                border-bottom: 2px solid #c3c4c7;
            }
            .oidc-status-table td {
                padding: 12px;
                border-bottom: 1px solid #f0f0f1;
            }
            .oidc-status-table tr:last-child td {
                border-bottom: none;
            }
            .oidc-status-icon {
                display: inline-flex;
                align-items: center;
                justify-content: center;
                width: 24px;
                height: 24px;
            }
            .oidc-status-icon.success {
                color: #00a32a;
            }
            .oidc-status-icon.error {
                color: #d63638;
            }
            .oidc-status-icon.warning {
                color: #dba617;
            }
        ';
        wp_add_inline_style('dashicons', $custom_css);
    }

    public function save_network_settings() {
        check_admin_referer('simple_oidc_network_settings', '_wpnonce_network_settings');

        if (!current_user_can('manage_network_options')) {
            wp_die('Access denied');
        }

        $old_options = get_site_option('simple_oidc_network_options', array());

        // Build new options array
        $new_options = array(
            'enabled' => (isset($_POST['enabled']) && $_POST['enabled'] === '1') ? '1' : '0',
            'logout_from_idp' => (isset($_POST['logout_from_idp']) && $_POST['logout_from_idp'] === '1') ? '1' : '0',
            'oidc_only' => (isset($_POST['oidc_only']) && $_POST['oidc_only'] === '1') ? '1' : '0',
            'auto_create_users' => (isset($_POST['auto_create_users']) && $_POST['auto_create_users'] === '1') ? '1' : '0',
            'add_users_to_all_sites' => (isset($_POST['add_users_to_all_sites']) && $_POST['add_users_to_all_sites'] === '1') ? '1' : '0',
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

            set_transient('simple_oidc_network_validation_errors', $validation_errors, 60);
            update_site_option('simple_oidc_network_options', $new_options);

            wp_redirect(add_query_arg(
                array(
                    'page' => 'simple-oidc-network',
                    'validation_error' => '1'
                ),
                network_admin_url('settings.php')
            ));
            exit;
        }

        update_site_option('simple_oidc_network_options', $new_options);

        wp_redirect(add_query_arg(
            array(
                'page' => 'simple-oidc-network',
                'updated' => 'true'
            ),
            network_admin_url('settings.php')
        ));
        exit;
    }

    public function test_network_connection() {
        check_admin_referer('simple_oidc_network_test', '_wpnonce_network_test');

        if (!current_user_can('manage_network_options')) {
            wp_die('Access denied');
        }

        // Reuse test logic from regular admin
        require_once SOIDC_DIR . 'admin/class-admin.php';
        $admin = new Simple_OIDC_Admin();

        // Override options to use network options
        $network_options = get_site_option('simple_oidc_network_options', array());
        add_filter('pre_option_simple_oidc_options', function() use ($network_options) {
            return $network_options;
        });

        $result = $admin->test_connection();

        set_transient('simple_oidc_network_test_result', json_encode($result), 60);

        wp_redirect(add_query_arg(
            array(
                'page' => 'simple-oidc-network',
                'tested' => 'true'
            ),
            network_admin_url('settings.php')
        ));
        exit;
    }

    public function network_settings_page() {
        if (!current_user_can('manage_network_options')) {
            return;
        }

        // Show success message
        $message = '';
        if (isset($_GET['updated']) && $_GET['updated'] === 'true') {
            $message = 'Network settings saved successfully!';
        }

        // Show validation errors
        $validation_errors = array();
        if (isset($_GET['validation_error']) && $_GET['validation_error'] === '1') {
            $validation_errors = get_transient('simple_oidc_network_validation_errors');
            if ($validation_errors) {
                delete_transient('simple_oidc_network_validation_errors');
            }
        }

        // Show test result
        $test_result = null;
        if (isset($_GET['tested']) && $_GET['tested'] === 'true') {
            $result_json = get_transient('simple_oidc_network_test_result');
            if ($result_json) {
                $test_result = json_decode($result_json, true);
                delete_transient('simple_oidc_network_test_result');
            }
        }

        // Load current network options
        $options = get_site_option('simple_oidc_network_options', array(
            'enabled' => '0',
            'logout_from_idp' => '0',
            'oidc_only' => '0',
            'auto_create_users' => '1',
            'add_users_to_all_sites' => '0',
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
        $add_users_to_all_sites = isset($options['add_users_to_all_sites']) ? ($options['add_users_to_all_sites'] === '1') : false;
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
                    <h1>OIDC SSO - Network Settings</h1>
                    <p style="margin: 5px 0 0 0; color: #646970;">Network-wide configuration for all sites</p>
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

            <div class="oidc-info-box">
                <span class="dashicons dashicons-info"></span>
                <strong>Multisite Mode:</strong> These settings apply to all sites in the network. Individual sites can override these settings if needed.
            </div>

            <?php if ($message): ?>
                <div class="oidc-card" style="border-left: 4px solid #00a32a; background: #f0fdf4;">
                    <div class="oidc-card-header" style="background: #f0fdf4; border-bottom: none; display: flex; justify-content: space-between; align-items: center;">
                        <div style="display: flex; align-items: center; gap: 8px;">
                            <span class="dashicons dashicons-yes-alt" style="color: #00a32a;"></span>
                            <span style="color: #00a32a; font-weight: 600;"><?php echo esc_html($message); ?></span>
                        </div>
                        <button type="button" class="button button-small" onclick="this.closest('.oidc-card').style.display='none';" style="border: none; background: none; cursor: pointer;">
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
                        <button type="button" class="button button-small" onclick="document.getElementById('test-results-card').style.display='none';">
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
                    Network Configuration
                </div>
                <div class="oidc-card-body">
                    <form method="post" action="<?php echo esc_url(network_admin_url('edit.php?action=simple_oidc_network_save')); ?>">
                        <?php wp_nonce_field('simple_oidc_network_settings', '_wpnonce_network_settings'); ?>

                        <table class="form-table" role="presentation">
                            <tr>
                                <th scope="row">
                                    <label for="enabled">Plugin Status</label>
                                </th>
                                <td>
                                    <label>
                                        <input type="checkbox" name="enabled" id="enabled" value="1" <?php echo $enabled ? 'checked="checked"' : ''; ?>>
                                        Enable OIDC authentication network-wide
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
                                        When <strong>disabled</strong>: Only existing WordPress users can log in via OIDC.
                                    </p>
                                </td>
                            </tr>

                            <tr>
                                <th scope="row">
                                    <label for="add_users_to_all_sites">Multisite User Scope</label>
                                </th>
                                <td>
                                    <label>
                                        <input type="checkbox" name="add_users_to_all_sites" id="add_users_to_all_sites" value="1" <?php echo $add_users_to_all_sites ? 'checked="checked"' : ''; ?>>
                                        Add new users to all sites in the network
                                    </label>
                                    <p class="description">
                                        When <strong>enabled</strong>: New users can access all sites in the network (as subscribers).<br>
                                        When <strong>disabled</strong>: New users can only access the site where they first logged in.
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
                            <button type="submit" class="button button-primary button-large">
                                <span class="dashicons dashicons-saved" style="margin-top: 4px;"></span>
                                Save Network Settings
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
                    <form method="post" action="<?php echo esc_url(network_admin_url('edit.php?action=simple_oidc_network_test')); ?>">
                        <?php wp_nonce_field('simple_oidc_network_test', '_wpnonce_network_test'); ?>
                        <p>
                            <button type="submit" class="button button-secondary">
                                <span class="dashicons dashicons-update" style="margin-top: 4px;"></span>
                                Run Connection Test
                            </button>
                        </p>
                    </form>
                </div>
            </div>

            <div class="oidc-card">
                <div class="oidc-card-header">
                    <span class="dashicons dashicons-admin-tools"></span>
                    System & Debug Information
                </div>
                <div class="oidc-card-body">
                    <p style="margin-top: 0;">Export system information for troubleshooting. Include this information when reporting issues on GitHub.</p>
                    <?php
                    // Reuse debug info from site admin
                    require_once SOIDC_DIR . 'admin/class-admin.php';
                    $admin = new Simple_OIDC_Admin();
                    $debug_info = $admin->get_debug_info();
                    $debug_text = $admin->export_debug_info_text();
                    ?>

                    <div style="background: #f6f7f7; border: 1px solid #c3c4c7; border-radius: 4px; padding: 15px; margin-bottom: 15px; max-height: 400px; overflow-y: auto;">
                        <?php foreach ($debug_info as $section => $data): ?>
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
                        <button type="button" class="button button-secondary" onclick="copyNetworkDebugInfo()">
                            <span class="dashicons dashicons-clipboard" style="margin-top: 4px;"></span>
                            Copy to Clipboard
                        </button>
                        <button type="button" class="button button-secondary" onclick="downloadNetworkDebugInfo()">
                            <span class="dashicons dashicons-download" style="margin-top: 4px;"></span>
                            Download as Text File
                        </button>
                    </div>

                    <textarea id="network-debug-info-text" style="display: none;"><?php echo esc_textarea($debug_text); ?></textarea>
                </div>
            </div>

            <script>
            function copyNetworkDebugInfo() {
                var debugText = document.getElementById('network-debug-info-text');
                var temp = document.createElement('textarea');
                temp.value = debugText.value;
                temp.style.position = 'fixed';
                temp.style.opacity = '0';
                document.body.appendChild(temp);
                temp.select();
                document.execCommand('copy');
                document.body.removeChild(temp);
                alert('Debug information copied to clipboard!');
            }

            function downloadNetworkDebugInfo() {
                var debugText = document.getElementById('network-debug-info-text').value;
                var blob = new Blob([debugText], { type: 'text/plain' });
                var url = window.URL.createObjectURL(blob);
                var a = document.createElement('a');
                a.href = url;
                a.download = 'simple-oidc-network-debug-info-' + Date.now() + '.txt';
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                window.URL.revokeObjectURL(url);
            }
            </script>

            <div class="oidc-info-box" style="border-left-color: #dba617; background: #fff8e5;">
                <span class="dashicons dashicons-info" style="color: #dba617;"></span>
                <strong>Site-specific Overrides:</strong> Individual sites can override these network settings by going to Settings → OIDC SSO on their site admin panel.
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
