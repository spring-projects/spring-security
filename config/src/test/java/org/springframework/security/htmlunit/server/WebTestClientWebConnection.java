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

import java.io.IOException;

import com.gargoylesoftware.htmlunit.WebClient;
import com.gargoylesoftware.htmlunit.WebConnection;
import com.gargoylesoftware.htmlunit.WebRequest;
import com.gargoylesoftware.htmlunit.WebResponse;

import org.springframework.lang.Nullable;
import org.springframework.test.web.reactive.server.FluxExchangeResult;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.util.Assert;

/**
 * @author Rob Winch
 * @since 5.0
 */
public class WebTestClientWebConnection implements WebConnection {

	private final WebTestClient webTestClient;

	private final String contextPath;

	private final HtmlUnitWebTestClient requestBuilder;

	private WebClient webClient;

	public WebTestClientWebConnection(WebTestClient webTestClient, WebClient webClient) {
		this(webTestClient, webClient, "");
	}

	public WebTestClientWebConnection(WebTestClient webTestClient, WebClient webClient, String contextPath) {
		Assert.notNull(webTestClient, "MockMvc must not be null");
		Assert.notNull(webClient, "WebClient must not be null");
		validateContextPath(contextPath);
		this.webClient = webClient;
		this.webTestClient = webTestClient;
		this.contextPath = contextPath;
		this.requestBuilder = new HtmlUnitWebTestClient(this.webClient, this.webTestClient);
	}

	/**
	 * Validate the supplied {@code contextPath}.
	 * <p>
	 * If the value is not {@code null}, it must conform to
	 * {@link jakarta.servlet.http.HttpServletRequest#getContextPath()} which states that
	 * it can be an empty string and otherwise must start with a "/" character and not end
	 * with a "/" character.
	 * @param contextPath the path to validate
	 */
	static void validateContextPath(@Nullable String contextPath) {
		if (contextPath == null || "".equals(contextPath)) {
			return;
		}
		Assert.isTrue(contextPath.startsWith("/"), () -> "contextPath '" + contextPath + "' must start with '/'.");
		Assert.isTrue(!contextPath.endsWith("/"), () -> "contextPath '" + contextPath + "' must not end with '/'.");
	}

	public void setWebClient(WebClient webClient) {
		Assert.notNull(webClient, "WebClient must not be null");
		this.webClient = webClient;
	}

	@Override
	public WebResponse getResponse(WebRequest webRequest) throws IOException {
		long startTime = System.currentTimeMillis();
		FluxExchangeResult<String> exchangeResult = this.requestBuilder.getResponse(webRequest);
		webRequest.setUrl(exchangeResult.getUrl().toURL());
		return new MockWebResponseBuilder(startTime, webRequest, exchangeResult).build();
	}

	@Override
	public void close() {
	}

}
