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

package org.springframework.security.htmlunit.server;

import java.net.URI;
import java.time.Duration;

import org.junit.jupiter.api.Test;
import org.openqa.selenium.WebDriver;
import reactor.core.publisher.Mono;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseCookie;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.web.util.TextEscapeUtils;
import org.springframework.stereotype.Controller;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Rob Winch
 * @since 5.0
 */
public class WebTestClientHtmlUnitDriverBuilderTests {

	@Test
	public void helloWorld() {
		WebTestClient webTestClient = WebTestClient.bindToController(new HelloWorldController()).build();
		// @formatter:off
		WebDriver driver = WebTestClientHtmlUnitDriverBuilder
				.webTestClientSetup(webTestClient)
				.build();
		// @formatter:on
		driver.get("http://localhost/");
		assertThat(driver.getPageSource()).contains("Hello World");
	}

	@Test
	public void cookies() {
		// @formatter:off
		WebTestClient webTestClient = WebTestClient
				.bindToController(new CookieController())
				.build();
		WebDriver driver = WebTestClientHtmlUnitDriverBuilder
				.webTestClientSetup(webTestClient)
				.build();
		// @formatter:on
		driver.get("http://localhost/cookie");
		assertThat(driver.getPageSource()).contains("theCookie");
		driver.get("http://localhost/cookie/delete");
		assertThat(driver.getPageSource()).contains("null");
	}

	@Controller
	class HelloWorldController {

		@ResponseBody
		@GetMapping(path = "/", produces = MediaType.TEXT_HTML_VALUE)
		String index() {
			// @formatter:off
			return "<html>\n"
				+ "<head>\n"
				+ "<title>Hello World</title>\n"
				+ "</head>\n"
				+ "<body>\n"
				+ "<h1>Hello World</h1>\n"
				+ "</body>\n"
				+ "</html>";
			// @formatter:on
		}

	}

	@Controller
	@ResponseBody
	class CookieController {

		@GetMapping(path = "/", produces = MediaType.TEXT_HTML_VALUE)
		String view(@CookieValue(required = false) String cookieName) {
			// @formatter:off
			return "<html>\n"
				+ "<head>\n"
				+ "<title>Hello World</title>\n"
				+ "</head>\n"
				+ "<body>\n"
				+ "<h1>"
				+ TextEscapeUtils.escapeEntities(cookieName)
				+ "</h1>\n"
				+ "</body>\n"
				+ "</html>";
			// @formatter:on
		}

		@GetMapping("/cookie")
		Mono<Void> setCookie(ServerHttpResponse response) {
			response.addCookie(ResponseCookie.from("cookieName", "theCookie").build());
			return redirect(response);
		}

		private Mono<Void> redirect(ServerHttpResponse response) {
			response.setStatusCode(HttpStatus.MOVED_PERMANENTLY);
			response.getHeaders().setLocation(URI.create("/"));
			return response.setComplete();
		}

		@GetMapping("/cookie/delete")
		Mono<Void> deleteCookie(ServerHttpResponse response) {
			response.addCookie(ResponseCookie.from("cookieName", "").maxAge(Duration.ofSeconds(0)).build());
			return redirect(response);
		}

	}

}
