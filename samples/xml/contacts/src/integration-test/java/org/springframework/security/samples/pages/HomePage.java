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

package org.springframework.security.samples.pages;

import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.support.FindBy;
import org.openqa.selenium.support.PageFactory;
import org.springframework.security.samples.pages.LoginPage;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The home page.
 *
 * @author Michael Simons
 */
public class HomePage {

	public static HomePage to(WebDriver driver, int port) {
		driver.get("http://localhost:" + port +"/");
		return PageFactory.initElements(driver, HomePage.class);
	}

	private final WebDriver webDriver;

	@FindBy(css = "p")
	private WebElement message;

	@FindBy(css = "input[type=submit]")
	private WebElement logoutButton;

	public HomePage(WebDriver webDriver) {
		this.webDriver = webDriver;
	}

	public Content assertAt() {
		assertThat(this.webDriver.getTitle()).isEqualTo("Contacts Security Demo");
		return PageFactory.initElements(this.webDriver, Content.class);
	}

	public LoginPage logout() {
		this.logoutButton.submit();
		return PageFactory.initElements(this.webDriver, LoginPage.class);
	}

	public static class Content {
		@FindBy(css = "p")
		private WebElement message;

		public Content andTheUserNameIsDisplayed() {
			assertThat(message.getText()).isEqualTo("Hello user");
			return this;
		}
	}
}
