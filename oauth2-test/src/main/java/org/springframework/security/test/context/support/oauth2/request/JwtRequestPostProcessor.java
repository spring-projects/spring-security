/*
 * Copyright 2002-2019 the original author or authors.
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
package org.springframework.security.test.context.support.oauth2.request;

import static org.junit.Assert.assertNotNull;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.test.context.support.oauth2.support.JwtSupport;
import org.springframework.security.test.web.servlet.request.SecurityContextRequestPostProcessorSupport;

/**
 * @author Jérôme Wacongne &lt;ch4mp@c4-soft.com&gt;
 * @since 5.2.0
 */
public class JwtRequestPostProcessor extends AbstractOAuth2RequestPostProcessor<JwtRequestPostProcessor> {

	private static Map<String, Object> DEFAULT_HEADERS =
			Collections.singletonMap(JwtSupport.DEFAULT_HEADER_NAME, JwtSupport.DEFAULT_HEADER_VALUE);

	private Map<String, Object> headers = DEFAULT_HEADERS;

	private boolean isHeadersSet = false;

	public JwtRequestPostProcessor() {
		super(JwtSupport.DEFAULT_AUTH_NAME, JwtSupport.DEFAULT_AUTHORITIES);
	}

	@Override
	public MockHttpServletRequest postProcessRequest(final MockHttpServletRequest request) {
		final Authentication authentication = JwtSupport.authentication(name, authorities, scopes, attributes, headers);
		SecurityContextRequestPostProcessorSupport.createSecurityContext(authentication, request);
		return request;
	}

	public JwtRequestPostProcessor claims(final Map<String, Object> claims) {
		return attributes(claims);
	}

	public JwtRequestPostProcessor claim(final String name, final Object value) {
		return attribute(name, value);
	}

	public JwtRequestPostProcessor headers(final Map<String, Object> headers) {
		headers.entrySet().stream().forEach(e -> this.header(e.getKey(), e.getValue()));
		return this;
	}

	public JwtRequestPostProcessor header(final String name, final Object value) {
		assertNotNull(name);
		if (this.isHeadersSet == false) {
			this.headers = new HashMap<>();
			this.isHeadersSet = true;
		}
		this.headers.put(name, value);
		return this;
	}

}
