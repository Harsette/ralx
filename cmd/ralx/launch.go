package main

// Replace this one value when the homepage and waitlist are confirmed.
// The reserved .invalid domain deliberately cannot collect user information.
const defaultHomepageURL = "https://example.invalid/ralx/waitlist"

func launchHomepageURL() string { return envOr("RALX_HOMEPAGE_URL", defaultHomepageURL) }
