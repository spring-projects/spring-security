/*
 * Copyright 2002-2018 the original author or authors.
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

package org.springframework.security.samples;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.htmlunit.HtmlUnitDriver;
import org.springframework.security.samples.pages.HomePage;
import org.springframework.security.samples.pages.LoginPage;

/**
 * @author Michael Simons
 */
public class HelloWorldJcTests {

	private WebDriver driver;

	private int port;

	@Before
	public void setup() {
		this.port = Integer.parseInt(System.getProperty("app.httpPort"));
		this.driver = new HtmlUnitDriver();
	}

	@After
	public void tearDown() {
		this.driver.quit();
	}

	@Test
	public void accessHomePageWithUnauthenticatedUserSendsToLoginPage() {
		final LoginPage loginPage = HomePage.to(this.driver, this.port);
		loginPage.assertAt();
	}

	@Test
	public void authenticatedUserIsSentToOriginalPage() {
		final HomePage homePage = HomePage.to(this.driver, this.port)
			.loginForm()
				.username("user")
				.password("password")
			.submit();
		homePage
			.assertAt()
			.andTheUserNameIsDisplayed();
	}

	@Test
	public void authenticatedUserLogsOut() {
		LoginPage loginPage = HomePage.to(this.driver, this.port)
			.loginForm()
				.username("user")
				.password("password")
			.submit()
			.logout();
		loginPage.assertAt();

		loginPage = HomePage.to(this.driver, this.port);
		loginPage.assertAt();
	}
}
