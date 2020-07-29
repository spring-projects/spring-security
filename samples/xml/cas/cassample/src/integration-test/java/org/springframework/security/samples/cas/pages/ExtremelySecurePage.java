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

package org.springframework.security.samples.cas.pages;

import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.support.FindBy;
import org.openqa.selenium.support.PageFactory;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Represents the extremely secure page of the CAS Sample application.
 *
 * @author Rob Winch
 * @author Josh Cummings
 */
public class ExtremelySecurePage extends Page<ExtremelySecurePage> {
	private final Content content;

	public ExtremelySecurePage(WebDriver driver, String baseUrl) {
		super(driver, baseUrl + "/secure/extreme");
		this.content = PageFactory.initElements(driver, Content.class);
	}

	@Override
	public ExtremelySecurePage assertAt() {
		assertThat(this.content.getText()).isEqualTo("VERY Secure Page");
		return this;
	}

	public static class Content {
		@FindBy(tagName="h1")
		WebElement header;

		public String getText() {
			return this.header.getText();
		}
	}
}
