package com.google.springframework.security.web.ssrf;

import static org.junit.jupiter.api.Assertions.*;

import java.net.UnknownHostException;
import org.junit.jupiter.api.Test;

class CustomDnsResolverTest {

	@Test
	void resolve() throws UnknownHostException {
		SsrfProtectionConfig config = new SsrfProtectionConfig();
		config.setAllowExternalIp(true);
		CustomDnsResolver t = new CustomDnsResolver(config);
		t.resolve("8.8.8.8");
	}
}
