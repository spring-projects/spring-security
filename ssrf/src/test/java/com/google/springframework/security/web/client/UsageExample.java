package com.google.springframework.security.web.client;

import com.google.springframework.security.web.client.BasicSSRFProtectionFilter.FilterMode;
import org.springframework.web.client.RestTemplate;

public class UsageExample {


	public static void example2() {
		RestTemplate exampleTemplate = SecureRestTemplateUtil.makeSecureHC5Template(
				SsrfProtectionConfig.makeBasicFilter(
						FilterMode.ALLOW_INTERNAL_BLOCK_EXTERNAL));

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
		RestTemplate exampleTemplate = SecureRestTemplateUtil.makeHC5Default();
		exampleTemplate.getForEntity("https://google.com", String.class);
	}

	public static void main(String[] args) {
		example1();
		example2();
	}

}
