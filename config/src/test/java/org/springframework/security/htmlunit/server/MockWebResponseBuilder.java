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
import java.util.ArrayList;
import java.util.List;

import com.gargoylesoftware.htmlunit.WebRequest;
import com.gargoylesoftware.htmlunit.WebResponse;
import com.gargoylesoftware.htmlunit.WebResponseData;
import com.gargoylesoftware.htmlunit.util.NameValuePair;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.test.web.reactive.server.FluxExchangeResult;
import org.springframework.util.Assert;

/**
 * @author Rob Winch
 * @since 5.0
 */
final class MockWebResponseBuilder {
	private final long startTime;

	private final WebRequest webRequest;

	private final FluxExchangeResult<String> exchangeResult;


	MockWebResponseBuilder(long startTime, WebRequest webRequest, FluxExchangeResult<String> exchangeResult) {
		Assert.notNull(webRequest, "WebRequest must not be null");
		Assert.notNull(exchangeResult, "FluxExchangeResult must not be null");
		this.startTime = startTime;
		this.webRequest = webRequest;
		this.exchangeResult = exchangeResult;
	}


	public WebResponse build() throws IOException {
		WebResponseData webResponseData = webResponseData();
		long endTime = System.currentTimeMillis();
		return new WebResponse(webResponseData, this.webRequest, endTime - this.startTime);
	}

	private WebResponseData webResponseData() {
		List<NameValuePair> responseHeaders = responseHeaders();
		HttpStatus status = this.exchangeResult.getStatus();
		return new WebResponseData(this.exchangeResult.getResponseBodyContent(), status.value(), status.getReasonPhrase(), responseHeaders);
	}

	private List<NameValuePair> responseHeaders() {
		HttpHeaders responseHeaders = this.exchangeResult.getResponseHeaders();
		List<NameValuePair> result = new ArrayList<>(responseHeaders.size());
		responseHeaders.forEach( (headerName, headerValues) ->
			headerValues.forEach( headerValue ->
				result.add(new NameValuePair(headerName, headerValue))
			)
		);
		return result;
	}

}
