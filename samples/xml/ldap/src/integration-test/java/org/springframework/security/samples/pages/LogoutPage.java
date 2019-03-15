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

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Logout Page is the same as login page with an additional message.
 *
 * @author Michael Simons
 */
public class LogoutPage extends LoginPage {
	@FindBy(css = "p")
	private WebElement p;

	public LogoutPage(WebDriver webDriver) {
		super(webDriver);
	}

	@Override
	public LogoutPage assertAt() {
		super.assertAt();

		assertThat(p.getText()).isEqualTo("You have been logged out");
		return this;
	}
}
