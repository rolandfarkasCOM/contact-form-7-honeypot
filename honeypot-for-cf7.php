<?php
/**
 * Plugin Name: Simple Honeypot for Contact Form 7
 * Plugin URI: https://github.com/rolandfarkasCOM/honeypot-for-cf7/
 * Description: A simple honeypot/spam blocker plugin for Contact Form 7.
 * Version: 1.0.6
 * Author: Roland Farkas
 * Author URI: https://rolandfarkas.com
 * License: GPLv3 or later
 * License URI: https://www.gnu.org/licenses/gpl-3.0.html
 * Text Domain: honeypot-for-cf7
 * Requires at least: 5.6
 * Tested up to: 6.6
 * Requires PHP: 7.0
 * Requires Plugins: contact-form-7
 */

// Exit if accessed directly
if (!defined('ABSPATH')) {
	exit;
}

// Hook into the 'wpcf7_form_hidden_fields' filter to add the hidden honeypot field, nonce field, and timestamp
add_filter('wpcf7_form_hidden_fields', 'shfcf7_add_random_honeypot_hidden_field_and_timestamp');

function shfcf7_add_random_honeypot_hidden_field_and_timestamp($hidden_fields) {
	// Generate a random field name
	$field_name = 'honeypot_' . str_replace('-', '_', wp_generate_uuid4());

	// Add the random field name to the hidden fields array
	$hidden_fields['honeypot_field_name'] = $field_name;
	$hidden_fields[$field_name] = '';

	// Add a timestamp to the hidden fields array
	$hidden_fields['cf7_honeypot_timestamp'] = time();

	return $hidden_fields;
}

// Hook into the 'wpcf7_validate' filter to check the honeypot field, nonce, and submission time
add_filter('wpcf7_validate', 'shfcf7_check_random_honeypot_field_and_time', 10, 2);

function shfcf7_check_random_honeypot_field_and_time($result, $tags) {
	// Retrieve and sanitize the field name from the hidden input
	if (isset($_POST['honeypot_field_name'])) {
		$field_name = sanitize_text_field(wp_unslash($_POST['honeypot_field_name']));
	} else {
		$field_name = '';
	}

	// Check the honeypot field value
	if ($field_name && isset($_POST[$field_name]) && !empty($_POST[$field_name])) {
		$result->invalidate('', __('Spam detected.', 'honeypot-for-cf7'));
	}

	// Check the time taken to submit the form
	if (isset($_POST['cf7_honeypot_timestamp'])) {
		$submission_time = time() - absint(sanitize_text_field(wp_unslash($_POST['cf7_honeypot_timestamp'])));
		// Set a minimum time in seconds (e.g., 4 seconds)
		$min_time = 4;

		if ($submission_time < 0 || $submission_time < $min_time) {
			$result->invalidate('', __('Form submitted too quickly. Please wait a few seconds before submitting again.', 'honeypot-for-cf7'));
		}
	}

	return $result;
}