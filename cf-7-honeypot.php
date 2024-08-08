<?php
/**
 * Plugin Name: Simple Honeypot for Contact Form 7
 * Plugin URI: https://plugins.mcms.io/honeypot-for-cf7
 * Description: Adds a hidden field with a random name to Contact Form 7 forms to block bot/spam submissions.
 * Version: 1.0.2
 * Author: Roland Farkas
 * Author URI: https://rolandfarkas.com
 * License: GPL3
 * License URI: https://www.gnu.org/licenses/gpl-3.0.html
 * Text Domain: honeypot-for-cf7
 * Requires at least: 4.9
 * Tested up to: 6.6
 */

// Exit if accessed directly
if (!defined('ABSPATH')) {
    exit;
}

// Hook into the 'wpcf7_form_hidden_fields' filter to add the hidden honeypot field, nonce field, and timestamp
add_filter('wpcf7_form_hidden_fields', 'add_random_honeypot_hidden_field_and_timestamp');

function add_random_honeypot_hidden_field_and_timestamp($hidden_fields) {
    // Generate a random field name
    $field_name = 'honeypot_' . wp_generate_password(8, false, false);

    // Add the random field name to the hidden fields array
    $hidden_fields['honeypot_field_name'] = $field_name;
    $hidden_fields[$field_name] = '';

    // Generate a nonce and add it to the hidden fields array
    $nonce = wp_create_nonce('cf7_honeypot_nonce');
    $hidden_fields['cf7_honeypot_nonce'] = $nonce;

    // Add a timestamp to the hidden fields array
    $hidden_fields['cf7_honeypot_timestamp'] = time();

    return $hidden_fields;
}

// Hook into the 'wpcf7_validate' filter to check the honeypot field, nonce, and submission time
add_filter('wpcf7_validate', 'check_random_honeypot_field_and_time', 10, 2);

function check_random_honeypot_field_and_time($result, $tags) {
    // Retrieve the field name from the hidden input
    $field_name = sanitize_text_field($_POST['honeypot_field_name']);

    // Verify nonce
    if (!isset($_POST['cf7_honeypot_nonce']) || !wp_verify_nonce($_POST['cf7_honeypot_nonce'], 'cf7_honeypot_nonce')) {
        $result->invalidate('', __('Nonce verification failed.', 'honeypot-for-cf7'));
    }

    // Check the honeypot field value
    if ($field_name && isset($_POST[$field_name]) && !empty($_POST[$field_name])) {
        $result->invalidate('', __('Spam detected.', 'honeypot-for-cf7'));
    }

    // Check the time taken to submit the form
    if (isset($_POST['cf7_honeypot_timestamp'])) {
        $submission_time = time() - intval($_POST['cf7_honeypot_timestamp']);
        // Set a minimum time in seconds (e.g., 4 seconds)
        $min_time = 4;

        if ($submission_time < $min_time) {
            $result->invalidate('', __('Form submitted too quickly. Please wait a few seconds before submitting again.', 'honeypot-for-cf7'));
        }
    }

    return $result;
}