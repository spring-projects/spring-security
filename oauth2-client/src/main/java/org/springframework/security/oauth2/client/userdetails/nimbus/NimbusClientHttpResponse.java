/*
 * Copyright 2012-2017 the original author or authors.
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
 */
package org.springframework.security.oauth2.client.userdetails.nimbus;

import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.http.client.AbstractClientHttpResponse;
import org.springframework.util.Assert;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;

/**
 * @author Joe Grandja
 */
final class NimbusClientHttpResponse extends AbstractClientHttpResponse {

	private final HTTPResponse httpResponse;

	private final HttpHeaders headers;

	NimbusClientHttpResponse(HTTPResponse httpResponse) {
		Assert.notNull(httpResponse, "httpResponse cannot be null");
		this.httpResponse = httpResponse;
		this.headers = new HttpHeaders();
		this.headers.setAll(httpResponse.getHeaders());
	}

	@Override
	public int getRawStatusCode() throws IOException {
		return this.httpResponse.getStatusCode();
	}

	@Override
	public String getStatusText() throws IOException {
		return String.valueOf(this.getRawStatusCode());
	}

	@Override
	public void close() {
	}

	@Override
	public InputStream getBody() throws IOException {
		InputStream inputStream = new ByteArrayInputStream(
				this.httpResponse.getContent().getBytes(Charset.forName("UTF-8")));
		return inputStream;
	}

	@Override
	public HttpHeaders getHeaders() {
		return this.headers;
	}
}