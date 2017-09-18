/*
 *
 * Copyright 2002-2017 the original author or authors.
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
 *
 */

package org.springframework.security.htmlunit.server;

import com.gargoylesoftware.htmlunit.WebClient;
import org.openqa.selenium.WebDriver;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.test.web.servlet.htmlunit.webdriver.WebConnectionHtmlUnitDriver;

/**
 * @author Rob Winch
 * @since 5.0
 */
public class WebTestClientHtmlUnitDriverBuilder {
	private final WebTestClient webTestClient;

	private WebTestClientHtmlUnitDriverBuilder(WebTestClient webTestClient) {
		this.webTestClient = webTestClient;
	}

	public WebDriver build() {
		WebConnectionHtmlUnitDriver driver = new WebConnectionHtmlUnitDriver();
		WebClient webClient = driver.getWebClient();
		WebTestClientWebConnection connection = new WebTestClientWebConnection(this.webTestClient, webClient);
		driver.setWebConnection(connection);
		return driver;
	}

	public static WebTestClientHtmlUnitDriverBuilder webTestClientSetup(WebTestClient webTestClient) {
		return new WebTestClientHtmlUnitDriverBuilder(webTestClient);
	}
}
