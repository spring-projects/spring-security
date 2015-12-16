package org.springframework.security.integration;

import net.sourceforge.jwebunit.junit.WebTester;

import static org.assertj.core.api.Assertions.*;

import org.springframework.security.core.session.SessionRegistry;
import org.testng.annotations.Test;

/**
 * @author Luke Taylor
 */
public class CustomConcurrentSessionManagementTests extends
		AbstractWebServerIntegrationTests {

	protected String getContextConfigLocations() {
		return "/WEB-INF/http-security-custom-concurrency.xml /WEB-INF/in-memory-provider.xml";
	}

	@Test
	public void maxConcurrentLoginsValueIsRespected() throws Exception {
		beginAt("secure/index.html");
		login("jimi", "jimispassword");
		// Login again
		System.out.println("Client: ******* Second login ******* ");
		WebTester tester2 = new WebTester();
		tester2.getTestContext().setBaseUrl(getBaseUrl());
		tester2.beginAt("secure/index.html");
		tester2.setTextField("username", "jimi");
		tester2.setTextField("password", "jimispassword");
		tester2.setIgnoreFailingStatusCodes(true);
		tester2.submit();
		assertThat(tester2.getServerResponse()).contains(
				"Maximum sessions of 1 for this principal exceeded");
	}

	@Test
	public void logoutClearsSessionRegistryAndAllowsSecondLogin() throws Exception {
		beginAt("secure/index.html");
		login("bessie", "bessiespassword");
		SessionRegistry reg = getAppContext().getBean(SessionRegistry.class);

		tester.gotoPage("/logout");

		// Login again
		System.out.println("Client: ******* Second login ******* ");
		WebTester tester2 = new WebTester();
		tester2.getTestContext().setBaseUrl(getBaseUrl());
		tester2.beginAt("secure/index.html");
		tester2.setTextField("username", "bessie");
		tester2.setTextField("password", "bessiespassword");
		tester2.setIgnoreFailingStatusCodes(true);
		tester2.submit();
		assertThat(tester2.getServerResponse()).contains("A secure page");
	}
}
