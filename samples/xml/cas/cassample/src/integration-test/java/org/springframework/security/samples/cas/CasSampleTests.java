/*
 * Copyright 2002-2011 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.samples.cas;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.htmlunit.HtmlUnitDriver;

import org.springframework.security.samples.cas.pages.AccessDeniedPage;
import org.springframework.security.samples.cas.pages.ExtremelySecurePage;
import org.springframework.security.samples.cas.pages.HomePage;
import org.springframework.security.samples.cas.pages.LocalLogoutPage;
import org.springframework.security.samples.cas.pages.LoginPage;
import org.springframework.security.samples.cas.pages.ProxyTicketSamplePage;
import org.springframework.security.samples.cas.pages.SecurePage;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests the CAS sample application using service tickets.
 *
 * @author Rob Winch
 * @author Josh Cummings
 */
public class CasSampleTests {
	private WebDriver driver = new HtmlUnitDriver();

	private String serviceUrl;
	private String serverUrl;

	private LoginPage login;

	private HomePage home;
	private SecurePage secure;
	private ExtremelySecurePage extremelySecure;
	private ProxyTicketSamplePage proxyTicketSample;
	private LocalLogoutPage localLogout;
	private AccessDeniedPage accessDenied;

	@Before
	public void setup() {
		String serverHost = System.getProperty("cas.server.host", "localhost:8443");
		this.serverUrl = "https://" + serverHost + "/cas";
		String serviceHost = System.getProperty("cas.service.host", "localhost:8443");
		this.serviceUrl = "https://" + serviceHost + "/cas-sample";
		this.login = new LoginPage(this.driver, this.serverUrl);
		this.home = new HomePage(this.driver, this.serviceUrl);
		this.secure = new SecurePage(this.driver, this.serviceUrl);
		this.extremelySecure = new ExtremelySecurePage(this.driver, this.serviceUrl);
		this.proxyTicketSample = new ProxyTicketSamplePage(this.driver, this.serviceUrl);
		this.localLogout = new LocalLogoutPage(this.driver, this.serviceUrl);
		this.accessDenied = new AccessDeniedPage(this.driver);
	}

	@After
	public void tearDown() {
		this.driver.close();
	}

	@Test
	public void homePageWhenUnauthenticatedUserThenSucceeds() {
		this.home.to().assertAt();
	}

	@Test
	public void extremelySecurePageWhenUnauthenticatedThenRequiresLogin() {
		this.extremelySecure.to();
		this.login.assertAt();
	}

	@Test
	public void authenticateWhenInvalidTicketThenFails() {
		this.driver.get(this.serviceUrl + "/login/cas?ticket=invalid");
		assertThat(this.driver.findElement(By.tagName("h2")).getText())
				.isEqualTo("Login to CAS failed!");
	}

	@Test
	public void securePageWhenUnauthenticatedThenRequiresLogin() {
		this.secure.to();
		this.login.assertAt();
	}

	@Test
	public void securePageWhenRoleUserThenDisplays() {
		this.login.to().login("scott");
		this.secure.to().assertAt();
	}

	@Test
	public void proxyTicketSamplePageWhenRoleUserThenDisplays() {
		this.login.to().login("scott");
		this.proxyTicketSample.to().assertAt();
	}

	@Test
	public void extremelySecurePageWhenRoleUserThenDenies() {
		this.login.to().login("scott");
		this.extremelySecure.to();
		this.accessDenied.assertAt();
	}

	@Test
	public void localLogoutLinkWhenClickedThenRedirectsToLocalLogoutPage() {
		this.login.to().login("scott");
		this.secure.to().logout();
		this.localLogout.assertAt();
	}

	@Test
	public void casLogoutWhenClickedThenPerformsCompleteLogout() {
		this.login.to().login("scott");
		this.driver.get(this.serverUrl + "/logout");
		this.secure.to();
		this.login.assertAt();
	}

	@Test
	public void extremelySecureWhenRoleSupervisorThenDisplays() {
		this.login.to().login("rod");
		this.extremelySecure.to().assertAt();
	}

	@Test
	public void casLogoutWhenClickedThenExtremelySecurePageRequiresLogin() {
		this.login.to().login("scott");
		this.driver.get(this.serverUrl + "/logout");
		this.extremelySecure.to();
		this.login.assertAt();
	}

	@Test
	public void casLogoutWhenVisitedThenLogsOutSample() {
		this.secure.to();
		this.login.assertAt().login("rod");
		this.secure.assertAt();
		this.driver.get(this.serverUrl + "/logout");
		this.secure.to();
		this.login.assertAt();
	}
}
