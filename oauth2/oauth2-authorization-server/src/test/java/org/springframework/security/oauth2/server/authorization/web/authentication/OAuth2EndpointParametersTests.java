/*
 * Copyright 2004-present the original author or authors.
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

package org.springframework.security.oauth2.server.authorization.web.authentication;

import org.junit.jupiter.api.Test;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.util.MultiValueMap;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link OAuth2EndpointParameters}.
 *
 * @author Joe Grandja
 */
public class OAuth2EndpointParametersTests {

	@Test
	public void getFormParametersWhenQueryAndFormParametersThenReturnsFormParameters() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setQueryString("query=query-value");
		request.addParameter("query", "query-value");
		request.addParameter("form", "form-value-1", "form-value-2");

		MultiValueMap<String, String> parameters = OAuth2EndpointParameters.getFormParameters(request);

		assertThat(parameters).containsOnlyKeys("form");
		assertThat(parameters.get("form")).containsExactly("form-value-1", "form-value-2");
	}

	@Test
	public void getQueryParametersWhenQueryAndFormParametersThenReturnsQueryParameters() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setQueryString("query=query-value-1&query=query-value-2");
		request.addParameter("query", "query-value-1", "query-value-2");
		request.addParameter("form", "form-value");

		MultiValueMap<String, String> parameters = OAuth2EndpointParameters.getQueryParameters(request);

		assertThat(parameters).containsOnlyKeys("query");
		assertThat(parameters.get("query")).containsExactly("query-value-1", "query-value-2");
	}

}
