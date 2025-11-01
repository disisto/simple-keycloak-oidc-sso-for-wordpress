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
 * Main Simple OIDC Class
 */
class Simple_OIDC {

    private static $instance = null;
    private $options;

    public static function get_instance() {
        if (null === self::$instance) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    private function __construct() {
        // Load options
        $this->options = get_option('simple_oidc_options', array(
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

        // Register hooks after WordPress is fully loaded
        add_action('init', array($this, 'register_hooks'));

        // Always init admin
        if (is_admin()) {
            require_once SOIDC_DIR . 'admin/class-admin.php';
            new Simple_OIDC_Admin();
        }
    }

    public function register_hooks() {
        // Always register logout hooks (even if plugin is disabled, for already logged in users)
        add_action('login_init', array($this, 'handle_idp_logout'));
        add_action('login_init', array($this, 'handle_frontchannel_logout'));

        // Register REST API endpoints for logout callbacks
        add_action('rest_api_init', array($this, 'register_rest_routes'));

        // Only init login hooks if enabled
        if (isset($this->options['enabled']) && $this->options['enabled'] === '1') {
            $this->init_hooks();
        }
    }

    private function init_hooks() {
        add_action('login_init', array($this, 'handle_callback'));
        add_action('login_init', array($this, 'handle_oidc_only_redirect'), 1);
        add_action('login_enqueue_scripts', array($this, 'enqueue_login_styles'));
        add_action('login_footer', array($this, 'add_login_button_top'));
        add_filter('get_avatar', array($this, 'get_oidc_avatar'), 10, 5);
        add_filter('get_avatar_url', array($this, 'get_oidc_avatar_url'), 10, 3);
    }

    /**
     * Redirect to identity provider directly if in OIDC-only mode
     * This runs on login_init with priority 1, before the login page is rendered
     */
    public function handle_oidc_only_redirect() {
        // Check if OIDC-only mode is enabled
        if (!isset($this->options['oidc_only']) || $this->options['oidc_only'] !== '1') {
            return;
        }

        // Don't redirect if user is already logged in
        if (is_user_logged_in()) {
            return;
        }

        // Don't redirect if already processing callback
        if (isset($_GET['code']) && isset($_GET['state'])) {
            return;
        }

        // Don't redirect if this is a logout action
        if (isset($_GET['action']) && $_GET['action'] === 'logout') {
            return;
        }

        // Don't redirect if user just logged out
        if (isset($_GET['loggedout']) && $_GET['loggedout'] === 'true') {
            return;
        }

        // Redirect directly to identity provider
        $login_url = $this->get_authorization_url();
        nocache_headers();
        wp_redirect($login_url);
        exit;
    }

    /**
     * Enqueue custom login page styles and scripts
     */
    public function enqueue_login_styles() {
        // Enqueue CSS
        wp_enqueue_style(
            'simple-oidc-login',
            SOIDC_URL . 'assets/css/login.css',
            array(),
            SOIDC_VERSION
        );

        // Enqueue JavaScript
        wp_enqueue_script(
            'simple-oidc-login',
            SOIDC_URL . 'assets/js/login.js',
            array(),
            SOIDC_VERSION,
            true
        );

        // Pass configuration to JavaScript
        $oidc_only = (isset($this->options['oidc_only']) && $this->options['oidc_only'] === '1');
        wp_localize_script(
            'simple-oidc-login',
            'simpleOidcConfig',
            array(
                'oidcOnly' => $oidc_only
            )
        );
    }

    /**
     * Add OIDC login button above login form (between logo and form)
     */
    public function add_login_button_top() {
        $login_url = $this->get_authorization_url();
        // Use default if button_text is empty
        $button_text = !empty($this->options['button_text']) ? $this->options['button_text'] : 'Single Sign-On (SSO)';
        $oidc_only = (isset($this->options['oidc_only']) && $this->options['oidc_only'] === '1');

        // Add SSO button in separate container - will be repositioned via JavaScript
        ?>
        <div id="oidc-sso-wrapper">
            <p class="oidc-sso-button">
                <a href="<?php echo esc_url($login_url); ?>"
                   class="button button-primary button-large">
                    <span class="dashicons dashicons-admin-network"></span>
                    <?php echo esc_html($button_text); ?>
                </a>
            </p>
        </div>

        <?php if (!$oidc_only): ?>
        <div class="oidc-separator">
             <span><?php esc_html_e('or', 'simple-oidc-sso'); ?></span>
        </div>
        <?php endif; ?>
        <?php
    }

    /**
     * Get authorization URL
     */
    private function get_authorization_url() {
        $state = wp_generate_password(32, false);
        $nonce = wp_generate_password(32, false);

        // Store state and nonce for 30 minutes (1800 seconds) to allow time for login
        set_transient('soidc_state_' . md5($state), $nonce, 1800);
        set_transient('soidc_nonce_' . md5($nonce), true, 1800);

        $params = array(
            'client_id' => $this->options['client_id'],
            'response_type' => 'code',
            'scope' => 'openid email profile',
            'redirect_uri' => wp_login_url(),
            'state' => $state,
            'nonce' => $nonce,
        );

        $auth_url = rtrim($this->options['server_url'], '/') .
                    '/realms/' . $this->options['realm'] .
                    '/protocol/openid-connect/auth';

        return $auth_url . '?' . http_build_query($params);
    }

    /**
     * Handle OIDC callback
     */
    public function handle_callback() {
        if (!isset($_GET['code']) || !isset($_GET['state'])) {
            return;
        }

        // If already logged in AND not a reauth request, redirect to admin and skip callback processing
        // Allow callback processing for reauth requests even if logged in
        $is_reauth = isset($_GET['reauth']) || (isset($_GET['redirect_to']) && strpos(wp_unslash($_GET['redirect_to']), 'reauth=1') !== false);
        if (is_user_logged_in() && !$is_reauth) {
            wp_redirect(admin_url());
            exit;
        }

        $code = sanitize_text_field(wp_unslash($_GET['code']));
        $state = sanitize_text_field(wp_unslash($_GET['state']));

        // Verify state
        $state_key = 'soidc_state_' . md5($state);
        $nonce = get_transient($state_key);

        if (!$nonce) {
            wp_die('Invalid state or session expired. Please try logging in again. <a href="' . esc_url(wp_login_url()) . '">Back to login</a>');
        }

        // Mark state as used (but don't delete yet, allow page reloads for 60 seconds)
        $used_key = 'soidc_used_' . md5($state);
        if (get_transient($used_key)) {
            // State already used, redirect to login
            wp_redirect(admin_url());
            exit;
        }
        set_transient($used_key, true, 60);

        // Delete state after marking as used
        delete_transient($state_key);

        // Exchange code for tokens
        $tokens = $this->exchange_code($code);

        if (is_wp_error($tokens)) {
            wp_die(esc_html($tokens->get_error_message()));
        }

        // Get user info
        $user_info = $this->get_user_info($tokens['access_token']);

        if (is_wp_error($user_info)) {
            wp_die(esc_html($user_info->get_error_message()));
        }

        // Create or update user
        $user = $this->create_or_update_user($user_info);

        if (is_wp_error($user)) {
            wp_die(esc_html($user->get_error_message()));
        }

        // Store id_token for logout (CRITICAL for automatic logout)
        if (isset($tokens['id_token']) && !empty($tokens['id_token'])) {
            update_user_meta($user->ID, 'oidc_id_token', $tokens['id_token']);

            // Extract and store session ID (sid) for logout propagation
            $token_parts = explode('.', $tokens['id_token']);
            if (count($token_parts) === 3) {
                $payload = json_decode(base64_decode(strtr($token_parts[1], '-_', '+/')), true);
                if (isset($payload['sid'])) {
                    update_user_meta($user->ID, 'oidc_session_id', $payload['sid']);
                }
                if (isset($payload['sub'])) {
                    update_user_meta($user->ID, 'oidc_sub', $payload['sub']);
                }
            }
        }

        // Log user in
        wp_set_current_user($user->ID);
        wp_set_auth_cookie($user->ID, true);
        do_action('wp_login', $user->user_login, $user);

        // Determine redirect URL
        $redirect_to = admin_url();

        // Check if there's a redirect_to parameter
        if (!empty($_REQUEST['redirect_to'])) {
            $redirect_to = esc_url_raw(wp_unslash($_REQUEST['redirect_to']));
            // Validate the redirect URL for security
            $redirect_to = wp_validate_redirect($redirect_to, admin_url());
        }

        // Use nocache headers to prevent browser caching issues
        nocache_headers();

        // Redirect
        wp_safe_redirect($redirect_to);
        exit;
    }

    /**
     * Exchange authorization code for tokens
     */
    private function exchange_code($code) {
        $token_url = rtrim($this->options['server_url'], '/') .
                     '/realms/' . $this->options['realm'] .
                     '/protocol/openid-connect/token';

        $response = wp_remote_post($token_url, array(
            'body' => array(
                'grant_type' => 'authorization_code',
                'code' => $code,
                'redirect_uri' => wp_login_url(),
                'client_id' => $this->options['client_id'],
                'client_secret' => $this->options['client_secret'],
            ),
        ));

        if (is_wp_error($response)) {
            return $response;
        }

        $body = wp_remote_retrieve_body($response);
        $data = json_decode($body, true);

        if (!isset($data['access_token'])) {
            return new WP_Error('token_error', 'Failed to get access token');
        }

        return $data;
    }

    /**
     * Get user info from identity provider
     */
    private function get_user_info($access_token) {
        $userinfo_url = rtrim($this->options['server_url'], '/') .
                        '/realms/' . $this->options['realm'] .
                        '/protocol/openid-connect/userinfo';

        $response = wp_remote_get($userinfo_url, array(
            'headers' => array(
                'Authorization' => 'Bearer ' . $access_token,
            ),
        ));

        if (is_wp_error($response)) {
            return $response;
        }

        $body = wp_remote_retrieve_body($response);
        $data = json_decode($body, true);

        if (!isset($data['sub'])) {
            return new WP_Error('userinfo_error', 'Failed to get user info');
        }

        return $data;
    }

    /**
     * Create or update WordPress user
     */
    private function create_or_update_user($user_info) {
        $oidc_id = $user_info['sub'];

        // Try to find existing user
        $users = get_users(array(
            'meta_key' => 'oidc_id',
            'meta_value' => $oidc_id,
            'number' => 1,
        ));

        $existing_user = null;

        if (!empty($users)) {
            $existing_user = $users[0];
        } else if (!empty($user_info['email'])) {
            // Try to find by email
            $existing_user = get_user_by('email', $user_info['email']);
            if ($existing_user) {
                update_user_meta($existing_user->ID, 'oidc_id', $oidc_id);
            }
        }

        // Update existing user
        if ($existing_user) {
            $user_data = array(
                'ID' => $existing_user->ID,
                'first_name' => $user_info['given_name'] ?? '',
                'last_name' => $user_info['family_name'] ?? '',
                'display_name' => $user_info['name'] ?? $existing_user->user_login,
            );

            wp_update_user($user_data);

            // Handle profile picture - use default 'picture' if not set
            $picture_claim = !empty($this->options['picture_claim']) ? $this->options['picture_claim'] : 'picture';
            if (!empty($user_info[$picture_claim])) {
                $this->update_user_avatar($existing_user->ID, $user_info[$picture_claim]);
            }

            return $existing_user;
        }

        // Check if automatic user creation is allowed
        $auto_create_users = isset($this->options['auto_create_users']) && $this->options['auto_create_users'] === '1';

        if (!$auto_create_users) {
            // User does not exist and auto-creation is disabled
            $error_message = sprintf(
                'Access denied. Your account (%s) is not authorized for this site. Please contact an administrator.',
                !empty($user_info['email']) ? $user_info['email'] : 'unknown'
            );
            return new WP_Error('user_not_authorized', $error_message);
        }

        // Create new user
        if (empty($user_info['email'])) {
            return new WP_Error('no_email', 'User has no email address');
        }

        $username = sanitize_user($user_info['preferred_username'] ?? $user_info['email']);

        // Make username unique
        $original_username = $username;
        $counter = 1;
        while (username_exists($username)) {
            $username = $original_username . $counter;
            $counter++;
        }

        $user_id = wp_insert_user(array(
            'user_login' => $username,
            'user_email' => $user_info['email'],
            'user_pass' => wp_generate_password(32),
            'first_name' => $user_info['given_name'] ?? '',
            'last_name' => $user_info['family_name'] ?? '',
            'display_name' => $user_info['name'] ?? $username,
        ));

        if (is_wp_error($user_id)) {
            return $user_id;
        }

        update_user_meta($user_id, 'oidc_id', $oidc_id);

        // Handle profile picture - use default 'picture' if not set
        $picture_claim = !empty($this->options['picture_claim']) ? $this->options['picture_claim'] : 'picture';
        if (!empty($user_info[$picture_claim])) {
            $this->update_user_avatar($user_id, $user_info[$picture_claim]);
        }

        return get_user_by('id', $user_id);
    }

    /**
     * Update user avatar from identity provider picture URL
     */
    private function update_user_avatar($user_id, $picture_url) {
        // Download and save the image
        require_once(ABSPATH . 'wp-admin/includes/file.php');
        require_once(ABSPATH . 'wp-admin/includes/media.php');
        require_once(ABSPATH . 'wp-admin/includes/image.php');

        $tmp = download_url($picture_url);

        if (is_wp_error($tmp)) {
            return;
        }

        $file_array = array(
            'name' => 'oidc-avatar-' . $user_id . '.jpg',
            'tmp_name' => $tmp
        );

        // Upload to media library
        $attachment_id = media_handle_sideload($file_array, 0);

        if (is_wp_error($attachment_id)) {
            wp_delete_file($tmp);
            return;
        }

        // Save attachment ID as user meta
        update_user_meta($user_id, 'oidc_avatar', $attachment_id);
    }

    /**
     * Handle identity provider logout
     * This runs on login_init, before the logout action is processed
     */
    public function handle_idp_logout() {
        // Only process if this is a logout request
        if (!isset($_GET['action']) || $_GET['action'] !== 'logout') {
            return;
        }

        // Only process if IDP logout is enabled
        if (!isset($this->options['logout_from_idp']) || $this->options['logout_from_idp'] !== '1') {
            return;
        }

        // Verify we have the required configuration
        if (empty($this->options['server_url']) || empty($this->options['realm']) || empty($this->options['client_id'])) {
            return;
        }

        // Check if user is logged in
        if (!is_user_logged_in()) {
            return;
        }

        // Verify nonce
        if (!isset($_GET['_wpnonce']) || !wp_verify_nonce($_GET['_wpnonce'], 'log-out')) {
            return;
        }

        // Get user ID and id_token before logout
        $user_id = get_current_user_id();
        $id_token = get_user_meta($user_id, 'oidc_id_token', true);

        // Determine redirect URI after IDP logout
        $redirect_to = !empty($_REQUEST['redirect_to']) ? esc_url_raw(wp_unslash($_REQUEST['redirect_to'])) : home_url();
        $redirect_to = wp_validate_redirect($redirect_to, home_url());

        // Perform WordPress logout
        wp_logout();

        // Clean up id_token
        if ($id_token) {
            delete_user_meta($user_id, 'oidc_id_token');
        }

        // Build identity provider logout URL with all required parameters
        $logout_params = array(
            'client_id' => $this->options['client_id'],
            'post_logout_redirect_uri' => $redirect_to,
        );

        // CRITICAL: id_token_hint is required to skip confirmation in some identity providers
        // Without it, the IDP may show "Are you sure?" page
        if (!empty($id_token)) {
            $logout_params['id_token_hint'] = $id_token;
        }

        $logout_url = rtrim($this->options['server_url'], '/') .
                     '/realms/' . $this->options['realm'] .
                     '/protocol/openid-connect/logout' .
                     '?' . http_build_query($logout_params);

        // Redirect to identity provider logout endpoint
        nocache_headers();
        wp_redirect($logout_url);
        exit;
    }

    /**
     * Register REST API routes for logout callbacks
     */
    public function register_rest_routes() {
        // Back-Channel Logout endpoint
        register_rest_route('simple-oidc/v1', '/backchannel-logout', array(
            'methods' => 'POST',
            'callback' => array($this, 'handle_backchannel_logout'),
            'permission_callback' => '__return_true', // Public endpoint for identity provider
        ));

        // Front-Channel Logout endpoint
        register_rest_route('simple-oidc/v1', '/frontchannel-logout', array(
            'methods' => 'GET',
            'callback' => array($this, 'handle_frontchannel_logout_rest'),
            'permission_callback' => '__return_true', // Public endpoint for identity provider
        ));
    }

    /**
     * Handle Back-Channel Logout from identity provider (Server-to-Server)
     * Called by identity provider when a user logs out from another application
     */
    public function handle_backchannel_logout($request) {
        // Get the logout token from POST body
        $logout_token = $request->get_param('logout_token');

        if (empty($logout_token)) {
            return new WP_Error('missing_token', 'No logout token provided', array('status' => 400));
        }

        // Decode the JWT token (without verification since it's from identity provider)
        $token_parts = explode('.', $logout_token);
        if (count($token_parts) !== 3) {
            return new WP_Error('invalid_token', 'Invalid token format', array('status' => 400));
        }

        $payload = json_decode(base64_decode(strtr($token_parts[1], '-_', '+/')), true);

        if (!isset($payload['sub'])) {
            return new WP_Error('invalid_payload', 'Missing subject in token', array('status' => 400));
        }

        // Find user by OIDC subject ID
        $users = get_users(array(
            'meta_key' => 'oidc_sub',
            'meta_value' => $payload['sub'],
            'number' => 1,
        ));

        if (empty($users)) {
            // User not found - this is OK, return success
            return new WP_REST_Response(array('status' => 'ok'), 200);
        }

        $user = $users[0];

        // Destroy all sessions for this user
        $sessions = WP_Session_Tokens::get_instance($user->ID);
        $sessions->destroy_all();

        // Clean up OIDC metadata
        delete_user_meta($user->ID, 'oidc_id_token');
        delete_user_meta($user->ID, 'oidc_access_token');

        return new WP_REST_Response(array('status' => 'ok'), 200);
    }

    /**
     * Handle Front-Channel Logout via REST API (Browser-based)
     */
    public function handle_frontchannel_logout_rest($request) {
        $sid = $request->get_param('sid');
        $iss = $request->get_param('iss');

        if (empty($sid)) {
            return new WP_Error('missing_sid', 'No session ID provided', array('status' => 400));
        }

        // Find user by session ID
        $users = get_users(array(
            'meta_key' => 'oidc_session_id',
            'meta_value' => $sid,
            'number' => 1,
        ));

        if (empty($users)) {
            // User not found or already logged out
            return new WP_REST_Response(array('status' => 'ok'), 200);
        }

        $user = $users[0];

        // Check if this is the current user - if so, log them out
        if (is_user_logged_in() && get_current_user_id() === $user->ID) {
            wp_logout();
        }

        // Destroy all sessions for this user
        $sessions = WP_Session_Tokens::get_instance($user->ID);
        $sessions->destroy_all();

        // Clean up metadata
        delete_user_meta($user->ID, 'oidc_id_token');
        delete_user_meta($user->ID, 'oidc_access_token');
        delete_user_meta($user->ID, 'oidc_session_id');

        return new WP_REST_Response(array('status' => 'ok'), 200);
    }

    /**
     * Handle Front-Channel Logout on login page (iframe loaded by identity provider)
     */
    public function handle_frontchannel_logout() {
        // Check if this is a front-channel logout request
        if (!isset($_GET['iss']) || !isset($_GET['sid'])) {
            return;
        }

        $sid = sanitize_text_field(wp_unslash($_GET['sid']));
        $iss = esc_url_raw(wp_unslash($_GET['iss']));

        // Verify issuer matches our identity provider server
        $expected_issuer = rtrim($this->options['server_url'], '/') . '/realms/' . $this->options['realm'];
        if ($iss !== $expected_issuer) {
            return;
        }

        // Find user by session ID
        $users = get_users(array(
            'meta_key' => 'oidc_session_id',
            'meta_value' => $sid,
            'number' => 1,
        ));

        if (empty($users)) {
            // Return empty response for iframe
            header('Content-Type: text/html; charset=utf-8');
            echo '<!DOCTYPE html><html><head><title>Logout</title></head><body></body></html>';
            exit;
        }

        $user = $users[0];

        // Check if this is the current user
        if (is_user_logged_in() && get_current_user_id() === $user->ID) {
            wp_logout();
        }

        // Destroy all sessions
        $sessions = WP_Session_Tokens::get_instance($user->ID);
        $sessions->destroy_all();

        // Clean up metadata
        delete_user_meta($user->ID, 'oidc_id_token');
        delete_user_meta($user->ID, 'oidc_access_token');
        delete_user_meta($user->ID, 'oidc_session_id');

        // Return empty response for iframe
        header('Content-Type: text/html; charset=utf-8');
        echo '<!DOCTYPE html><html><head><title>Logout</title></head><body></body></html>';
        exit;
    }

    /**
     * Filter to replace default avatar with OIDC avatar
     */
    public function get_oidc_avatar($avatar, $id_or_email, $size, $default, $alt) {
        $user = false;

        if (is_numeric($id_or_email)) {
            $user = get_user_by('id', $id_or_email);
        } elseif (is_object($id_or_email)) {
            if (!empty($id_or_email->user_id)) {
                $user = get_user_by('id', $id_or_email->user_id);
            }
        } else {
            $user = get_user_by('email', $id_or_email);
        }

        if (!$user || is_wp_error($user)) {
            return $avatar;
        }

        $avatar_id = get_user_meta($user->ID, 'oidc_avatar', true);

        if (!$avatar_id) {
            return $avatar;
        }

        $avatar_url = wp_get_attachment_url($avatar_id);

        if (!$avatar_url) {
            return $avatar;
        }

        $avatar = sprintf(
            '<img alt="%s" src="%s" class="avatar avatar-%d photo" height="%d" width="%d" loading="lazy" decoding="async" />',
            esc_attr($alt),
            esc_url($avatar_url),
            (int) $size,
            (int) $size,
            (int) $size
        );

        return $avatar;
    }

    /**
     * Filter to replace default avatar URL with OIDC avatar URL
     */
    public function get_oidc_avatar_url($url, $id_or_email, $args) {
        $user = false;

        if (is_numeric($id_or_email)) {
            $user = get_user_by('id', $id_or_email);
        } elseif (is_object($id_or_email)) {
            if (!empty($id_or_email->user_id)) {
                $user = get_user_by('id', $id_or_email->user_id);
            }
        } else {
            $user = get_user_by('email', $id_or_email);
        }

        if (!$user || is_wp_error($user)) {
            return $url;
        }

        $avatar_id = get_user_meta($user->ID, 'oidc_avatar', true);

        if (!$avatar_id) {
            return $url;
        }

        $avatar_url = wp_get_attachment_url($avatar_id);

        return $avatar_url ? $avatar_url : $url;
    }
}