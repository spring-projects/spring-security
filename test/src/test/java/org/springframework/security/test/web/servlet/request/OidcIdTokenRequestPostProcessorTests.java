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
package org.springframework.security.test.web.servlet.request;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.OAuth2SecurityMockMvcRequestPostProcessors.oidcId;

import java.util.Collections;

import org.junit.Test;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.authentication.OAuth2LoginAuthenticationToken;

/**
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 * @since 5.2
 */
public class OidcIdTokenRequestPostProcessorTests extends AbstractRequestPostProcessorTests {

	@SuppressWarnings("unchecked")
	@Test
	public void test() {
		final OidcIdTokenRequestPostProcessor rpp = oidcId().name(TEST_NAME)
				.authorities(TEST_AUTHORITIES)
				.claim("scope", Collections.singleton("test:claim"));

		final OAuth2LoginAuthenticationToken actual =
				(OAuth2LoginAuthenticationToken) authentication(rpp.postProcessRequest(request));

		assertThat(actual.getName()).isEqualTo(TEST_NAME);
		assertThat(actual.getAuthorities()).containsExactlyInAnyOrder(
				new SimpleGrantedAuthority("TEST_AUTHORITY"),
				new SimpleGrantedAuthority("SCOPE_test:claim"));
		assertThat(actual.getAccessToken().getScopes()).containsExactlyInAnyOrder("test:claim");
		assertThat(actual.getPrincipal().getAttributes().get("sub")).isEqualTo(TEST_NAME);
	}

}
