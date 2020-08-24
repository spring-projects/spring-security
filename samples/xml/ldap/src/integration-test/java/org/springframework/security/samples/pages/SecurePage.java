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
 * A secure page.
 *
 * @author Michael Simons
 */
public class SecurePage {

	public static LoginPage to(WebDriver driver, int port) {
		driver.get("http://localhost:" + port + "/secure");
		return PageFactory.initElements(driver, LoginPage.class);
	}

	private final WebDriver webDriver;

	@FindBy(css = "input[type=submit]")
	private WebElement submit;

	public SecurePage(WebDriver webDriver) {
		this.webDriver = webDriver;
	}

	public SecurePage assertAt() {
		assertThat(this.webDriver.getTitle()).isEqualTo("Secure Page");
		return this;
	}

	public LogoutPage logout() {
		this.submit.click();
		return PageFactory.initElements(this.webDriver, LogoutPage.class);
	}
}
