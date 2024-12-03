package com.google.springframework.security.web.client;

import static com.google.springframework.security.web.client.NetworkMode.BLOCK_EXTERNAL;

import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestTemplate;

public class UsageExample {

	public static void example3() {
		RestTemplate exampleTemplate = new SecureRestTemplate.Builder()
				.reportOnly(true) // Log warning about blocking, but don't block
				.networkMode(BLOCK_EXTERNAL)
				.withBlocklist(new String[]{"evil.com"})
				.build();

		try {
			ResponseEntity<String> result = exampleTemplate.getForEntity("https://google.com", String.class);
			System.out.println(result);
		} catch (Exception e) {
			// This should not run
			System.err.println("Access blocked: " + e.getMessage());
		}
	}

	public static void example2() {
		RestTemplate exampleTemplate = new SecureRestTemplate.Builder()
				.networkMode(BLOCK_EXTERNAL)
				.build();

		try {
			exampleTemplate.getForEntity("https://google.com", String.class);
		} catch (Exception e) {
			System.err.println("Access blocked: " + e.getMessage());
		}

		// This should print:
		// Access blocked: I/O error on GET request for "https://google.com": Access to google.com was blocked because it violates the SSRF protection config

	}

	public static void example1() {
		// run with `-Dssrf.protection.mode=deny_list -Dssrf.protection.iplist=127.0.0.1,192.168.0.0/16`
		// if the properties are not set accordingly it will fail with IllegalStateException

		// for this example:
		System.setProperty("ssrf.protection.mode", "deny_list");
		System.setProperty("ssrf.protection.iplist", "127.0.0.1,192.168.0.0/16");

		RestTemplate exampleTemplate = SecureRestTemplate.buildDefault();
		exampleTemplate.getForEntity("https://google.com", String.class);
	}

	public static void main(String[] args) {
		example1();
		example2();
		example3();
	}

}

