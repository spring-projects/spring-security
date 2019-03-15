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

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The login page.
 *
 * @author Michael Simons
 */
public class LoginPage {

	private final WebDriver webDriver;

	private final LoginForm loginForm;

	public LoginPage(WebDriver webDriver) {
		this.webDriver = webDriver;
		this.loginForm = PageFactory.initElements(this.webDriver, LoginForm.class);
	}

	public LoginPage assertAt() {
		assertThat(this.webDriver.getTitle()).isEqualTo("Login Page");
		return this;
	}

	public LoginForm loginForm() {
		return this.loginForm;
	}

	public static class LoginForm {
		private WebDriver webDriver;
		private WebElement username;
		private WebElement password;
		@FindBy(css = "input[type=submit]")
		private WebElement submit;

		public LoginForm(WebDriver webDriver) {
			this.webDriver = webDriver;
		}

		public LoginForm username(String username) {
			this.username.sendKeys(username);
			return this;
		}

		public LoginForm password(String password) {
			this.password.sendKeys(password);
			return this;
		}

		public SecurePage submit() {
			this.submit.click();
			return PageFactory.initElements(this.webDriver, SecurePage.class);
		}
	}
}
