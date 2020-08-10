/*
 * Copyright 2002-2020 the original author or authors.
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

package org.springframework.security.saml2.provider.service.web;

import org.junit.Test;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.saml2.provider.service.registration.InMemoryRelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.springframework.security.saml2.provider.service.registration.TestRelyingPartyRegistrations.relyingPartyRegistration;

/**
 * Tests for {@link DefaultRelyingPartyRegistrationResolver}
 */
public class DefaultRelyingPartyRegistrationResolverTests {

	private final RelyingPartyRegistration registration = relyingPartyRegistration().build();

	private final RelyingPartyRegistrationRepository repository = new InMemoryRelyingPartyRegistrationRepository(
			this.registration);

	private final DefaultRelyingPartyRegistrationResolver resolver = new DefaultRelyingPartyRegistrationResolver(
			this.repository);

	@Test
	public void resolveWhenRequestContainsRegistrationIdThenResolves() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setPathInfo("/some/path/" + this.registration.getRegistrationId());
		RelyingPartyRegistration registration = this.resolver.convert(request);
		assertThat(registration).isNotNull();
		assertThat(registration.getRegistrationId()).isEqualTo(this.registration.getRegistrationId());
		assertThat(registration.getEntityId())
				.isEqualTo("http://localhost/saml2/service-provider-metadata/" + this.registration.getRegistrationId());
		assertThat(registration.getAssertionConsumerServiceLocation())
				.isEqualTo("http://localhost/login/saml2/sso/" + this.registration.getRegistrationId());
	}

	@Test
	public void resolveWhenRequestContainsInvalidRegistrationIdThenNull() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setPathInfo("/some/path/not-" + this.registration.getRegistrationId());
		RelyingPartyRegistration registration = this.resolver.convert(request);
		assertThat(registration).isNull();
	}

	@Test
	public void resolveWhenRequestIsMissingRegistrationIdThenNull() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		RelyingPartyRegistration registration = this.resolver.convert(request);
		assertThat(registration).isNull();
	}

	@Test
	public void constructorWhenNullRelyingPartyRegistrationThenIllegalArgument() {
		assertThatCode(() -> new DefaultRelyingPartyRegistrationResolver(null))
				.isInstanceOf(IllegalArgumentException.class);
	}

}
