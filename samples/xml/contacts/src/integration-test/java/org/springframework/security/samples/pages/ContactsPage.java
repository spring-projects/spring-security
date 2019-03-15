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

import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.support.FindBy;
import org.openqa.selenium.support.PageFactory;
import org.springframework.security.samples.pages.AddPage.AddForm;

import java.util.List;
import java.util.function.Predicate;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The contacts / manage page.
 *
 * @author Michael Simons
 */
public class ContactsPage {
	public static LoginPage accessManagePageWithUnauthenticatedUser(WebDriver driver, int port) {
		driver.get("http://localhost:" + port +"/secure/");
		return PageFactory.initElements(driver, LoginPage.class);
	}

	private final WebDriver webDriver;

	@FindBy(linkText = "Add")
	private WebElement a;

	@FindBy(css = "table tr")
	private List<WebElement> contacts;

	@FindBy(xpath = "//input[@type='submit' and @value='Logoff']")
	private WebElement logout;

	public ContactsPage(WebDriver webDriver) {
		this.webDriver = webDriver;
	}

	public ContactsPage isAtContactsPage() {
		assertThat(this.webDriver.getTitle()).isEqualTo("Your Contacts");
		return this;
	}

	public AddForm addContact() {
		a.click();
		final AddPage addPage = PageFactory.initElements(this.webDriver, AddPage.class);
		return addPage.addForm();
	}

	Predicate<WebElement> byEmail(final String val) {
		return e -> e.findElements(By.xpath("td[position()=3 and normalize-space()='" + val + "']")).size() == 1;
	}

	Predicate<WebElement> byName(final String val) {
		return e -> e.findElements(By.xpath("td[position()=2 and normalize-space()='" + val + "']")).size() == 1;
	}

	public DeleteContactLink andHasContact(final String name, final String email) {
		return this.contacts.stream()
			.filter(byEmail(email).and(byName(name)))
			.map(e -> e.findElement(By.cssSelector("td:nth-child(4) > a")))
			.findFirst()
			.map(e -> new DeleteContactLink(webDriver, e))
			.get();
	}

	public ContactsPage andConctactHasBeenRemoved(final String name, final String email) {
		assertThat(this.contacts.stream()
			.filter(byEmail(email).and(byName(name)))
			.findAny()).isEmpty();
		return this;
	}

	public HomePage logout() {
		this.logout.click();
		return PageFactory.initElements(this.webDriver, HomePage.class);
	}

	public static class DeleteContactLink {

		private final WebDriver webDriver;

		private final WebElement a;

		public DeleteContactLink(WebDriver webDriver, WebElement a) {
			this.webDriver = webDriver;
			this.a = a;
		}

		public DeleteConfirmationPage delete() {
			this.a.click();
			return PageFactory.initElements(this.webDriver, DeleteConfirmationPage.class);
		}
	}

	public static class DeleteConfirmationPage {
		private final WebDriver webDriver;

		@FindBy(linkText = "Manage")
		private WebElement a;


		public DeleteConfirmationPage(WebDriver webDriver) {
			this.webDriver = webDriver;
		}

		public ContactsPage andConfirmDeletion() {
			assertThat(this.webDriver.getTitle()).isEqualTo("Deletion completed");
			this.a.click();
			return PageFactory.initElements(this.webDriver, ContactsPage.class);
		}
	}
}
