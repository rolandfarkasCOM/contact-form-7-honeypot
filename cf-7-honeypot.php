<?php
/**
 * Plugin Name: Simple Contact Form 7 Honeypot
 * Description: Adds a hidden field with a random name to Contact Form 7 forms to block bot/spam submissions.
 * Version: 1.0.0
 * Author: Roland Farkas
 * Author URI: https://rolandfarkas.com
 * License: GPL3
 * License URI: https://www.gnu.org/licenses/gpl-3.0.html
 * Text Domain: cf-7-honeypot
 * Requires at least: 4.9
 * Tested up to: 6.5.3
 */

// Exit if accessed directly
if (!defined('ABSPATH')) {
    exit;
}

// Hook into the 'wpcf7_form_hidden_fields' filter to add the hidden honeypot field
add_filter('wpcf7_form_hidden_fields', 'add_random_honeypot_hidden_field');

function add_random_honeypot_hidden_field($hidden_fields) {
    // Generate a random field name
    $field_name = 'honeypot_' . wp_generate_password(8, false, false);

    // Add the random field name to the hidden fields array
    $hidden_fields['honeypot_field_name'] = $field_name;
	$hidden_fields[$field_name] = '';

    return $hidden_fields;
}

// Hook into the 'wpcf7_validate' filter to check the honeypot field on form submission
add_filter('wpcf7_validate', 'check_random_honeypot_field', 10, 2);

function check_random_honeypot_field($result, $tags) {
    // Retrieve the field name from the hidden input
    $field_name = sanitize_text_field($_POST['honeypot_field_name']);

    // Check the honeypot field value
    if ($field_name && isset($_POST[$field_name]) && !empty($_POST[$field_name])) {
		error_log($_POST[$field_name]);
        $result->invalidate('', __('Spam detected.', 'cf-7-honeypot'));
    }

    return $result;
}