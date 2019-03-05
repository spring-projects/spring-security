/*
 * Copyright 2002-2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package sample.hello;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.openqa.selenium.WebDriver;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;
import sample.hello.pages.HomePage;
import sample.hello.pages.LoginPage;

/**
 * @author Michael Simons
 */
@SpringBootTest
@AutoConfigureMockMvc
@RunWith(SpringRunner.class)
public class HelloWorldApplicationTests {

	@Autowired
	private WebDriver driver;

	@Test
	public void accessHomePageWithUnauthenticatedUserSendsToLoginPage() {
		final LoginPage loginPage = HomePage.to(this.driver);
		loginPage.assertAt();
	}

	@Test
	public void authenticatedUserIsSentToOriginalPage() {
		final HomePage homePage = HomePage.to(this.driver)
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
		LoginPage loginPage = HomePage.to(this.driver)
			.loginForm()
				.username("user")
				.password("password")
			.submit()
			.logout();
		loginPage.assertAt();

		loginPage = HomePage.to(this.driver);
		loginPage.assertAt();
	}
}
