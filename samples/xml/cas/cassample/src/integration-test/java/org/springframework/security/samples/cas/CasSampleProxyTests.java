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

import java.util.HashMap;
import java.util.Map;

import org.jasig.cas.client.proxy.Cas20ProxyRetriever;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.htmlunit.HtmlUnitDriver;

import org.springframework.security.samples.cas.pages.AccessDeniedPage;
import org.springframework.security.samples.cas.pages.ExtremelySecurePage;
import org.springframework.security.samples.cas.pages.LoginPage;
import org.springframework.security.samples.cas.pages.ProxyTicketSamplePage;
import org.springframework.security.samples.cas.pages.SecurePage;
import org.springframework.security.samples.cas.pages.UnauthorizedPage;

/**
 * Tests authenticating to the CAS Sample application using Proxy Tickets. Geb is used to authenticate the {@link JettyCasService}
 * to the CAS Server in order to obtain the Ticket Granting Ticket. Afterwards HttpClient is used for accessing the CAS Sample application
 * using Proxy Tickets obtained using the Proxy Granting Ticket.
 *
 * @author Rob Winch
 * @author Josh Cummings
 */
public class CasSampleProxyTests {
	private static String serverUrl;
	private static String serviceUrl;
	private static JettyCasService service;
	private static Cas20ProxyRetriever retriever;

	private WebDriver driver = new HtmlUnitDriver();

	private LoginPage login;
	private SecurePage secure;
	private ExtremelySecurePage extremelySecure;
	private ProxyTicketSamplePage proxyTicketSample;
	private AccessDeniedPage accessDenied;
	private UnauthorizedPage unauthorized;

	@BeforeClass
	public static void setupClass() {
		String serverHost = System.getProperty("cas.server.host", "localhost:8443");
		serverUrl = "https://" + serverHost + "/cas";
		String serviceHost = System.getProperty("cas.service.host", "localhost:8443");
		serviceUrl = "https://" + serviceHost + "/cas-sample";
		service = new JettyCasService().init(serverUrl);
		retriever = new Cas20ProxyRetriever(serverUrl, "UTF-8");
	}

	@AfterClass
	public static void teardownClass() throws Exception {
		service.stop();
	}

	@Before
	public void setup() {
		this.login = new LoginPage(this.driver, serverUrl);
		this.secure = new SecurePage(this.driver, serviceUrl);
		this.extremelySecure = new ExtremelySecurePage(this.driver, serviceUrl);
		this.proxyTicketSample = new ProxyTicketSamplePage(this.driver, serviceUrl);
		this.accessDenied = new AccessDeniedPage(this.driver);
		this.unauthorized = new UnauthorizedPage(this.driver);
	}

	@After
	public void teardown() {
		this.driver.close();
	}

	@Test
	public void securePageWhenRoleUserThenDisplays() {
		this.login.to(this::serviceParam).assertAt().login("scott");
		this.secure.to(this::ticketParam).assertAt();
	}

	@Test
	public void proxyTicketSamplePageWhenRoleUserThenDisplays() {
		this.login.to(this::serviceParam).assertAt().login("scott");
		this.proxyTicketSample.to(this::ticketParam).assertAt();
	}

	@Test
	public void extremelySecurePageWhenRoleUserThenDenies() {
		this.login.to(this::serviceParam).assertAt().login("scott");
		this.extremelySecure.to(this::ticketParam);
		this.accessDenied.assertAt();
	}

	@Test
	public void extremelySecurePageWhenRoleSupervisorThenDisplays() {
		this.login.to(this::serviceParam).assertAt().login("rod");
		this.extremelySecure.to(this::ticketParam).assertAt();
	}

	@Test
	public void extremelySecurePageWhenReusingTicketThenDisplays() {
		this.login.to(this::serviceParam).assertAt().login("rod");
		Map<String, String> ptCache = new HashMap<>();
		this.extremelySecure.to(url -> url + "?ticket=" + ptCache.computeIfAbsent(url, this::getPt)).assertAt();
		this.extremelySecure.to(url -> url + "?ticket=" + ptCache.get(url)).assertAt();
	}

	@Test
	public void securePageWhenInvalidTicketThenFails() {
		this.login.to(this::serviceParam).assertAt().login("scott");
		this.secure.to(url -> url + "?ticket=invalid");
		this.unauthorized.assertAt();
	}

	private String serviceParam(String url) {
		return url + "?service=" + service.serviceUrl();
	}

	private String ticketParam(String url) {
		return url + "?ticket=" + getPt(url);
	}

	/**
	 * Obtains a proxy ticket using the pgt from the {@link #service}.
	 * @param targetService the targetService that the proxy ticket will be valid for
	 * @return a proxy ticket for targetService
	 */
	String getPt(String targetService) {
		assert service.pgt != null;
		return retriever.getProxyTicketIdFor(service.pgt, targetService);
	}
}
