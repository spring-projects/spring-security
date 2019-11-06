/*
 * Copyright 2002-2017 the original author or authors.
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
package sample;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.htmlunit.HtmlUnitDriver;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.web.server.LocalServerPort;
import org.springframework.test.context.junit4.SpringRunner;

import com.gargoylesoftware.htmlunit.BrowserVersion;

import sample.webdriver.IndexPage;
import sample.webdriver.LoginPage;

/**
 * @author Rob Winch
 * @since 5.0
 */
@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
public class WebfluxFormApplicationTests {
	WebDriver driver;

	@LocalServerPort
	int port;

	@Before
	public void setup() {
		this.driver = new HtmlUnitDriver(BrowserVersion.CHROME);
	}

	@Test
	public void loginWhenInvalidUsernameThenError() {
		LoginPage login = IndexPage.to(this.driver, this.port, LoginPage.class);
		login.assertAt();

		login
			.loginForm()
			.username("invalid")
			.password("password")
			.submit(LoginPage.class)
			.assertError();
	}

	@Test
	public void loginAndLogout() {
		LoginPage login = IndexPage.to(this.driver, this.port, LoginPage.class);
		login.assertAt();

		IndexPage index = login
			.loginForm()
				.username("user")
				.password("password")
				.submit(IndexPage.class);
		index.assertAt();

		login = index.logout();
		login
			.assertAt()
			.assertLogout();
	}
}
