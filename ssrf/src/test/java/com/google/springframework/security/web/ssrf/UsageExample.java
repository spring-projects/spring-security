package com.google.springframework.security.web.ssrf;

import com.google.springframework.security.web.ssrf.BasicSSRFProtectionFilter.FilterMode;
import org.springframework.web.client.RestTemplate;

public class UsageExample {

	public static void main(String[] args) {
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

}
