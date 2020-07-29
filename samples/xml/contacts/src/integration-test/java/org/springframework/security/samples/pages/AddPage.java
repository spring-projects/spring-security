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
 * @author Michael Simons
 */
public class AddPage {

	private final WebDriver webDriver;

	private final AddForm addForm;

	public AddPage(WebDriver webDriver) {
		this.webDriver = webDriver;
		this.addForm = PageFactory.initElements(this.webDriver, AddForm.class);
	}

	AddForm addForm() {
		assertThat(this.webDriver.getTitle()).isEqualTo("Add New Contact");
		return this.addForm;
	}

	public static class AddForm {
		private WebDriver webDriver;
		private WebElement name;
		private WebElement email;
		@FindBy(css = "input[type=submit]")
		private WebElement submit;

		public AddForm(WebDriver webDriver) {
			this.webDriver = webDriver;
		}

		public AddForm name(String name) {
			this.name.sendKeys(name);
			return this;
		}

		public AddForm email(String email) {
			this.email.sendKeys(email);
			return this;
		}

		public ContactsPage submit() {
			this.submit.click();
			return PageFactory.initElements(this.webDriver, ContactsPage.class);
		}
	}
}
