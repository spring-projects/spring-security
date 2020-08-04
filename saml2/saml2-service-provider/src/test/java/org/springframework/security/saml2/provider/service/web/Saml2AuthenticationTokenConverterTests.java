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

import javax.servlet.http.HttpServletRequest;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import org.springframework.core.convert.converter.Converter;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.saml2.core.Saml2Utils;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationToken;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.security.saml2.provider.service.registration.TestRelyingPartyRegistrations.relyingPartyRegistration;

@RunWith(MockitoJUnitRunner.class)
public class Saml2AuthenticationTokenConverterTests {
	@Mock
	Converter<HttpServletRequest, RelyingPartyRegistration> relyingPartyRegistrationResolver;

	RelyingPartyRegistration relyingPartyRegistration = relyingPartyRegistration().build();

	@Test
	public void convertWhenSamlResponseThenToken() {
		Saml2AuthenticationTokenConverter converter = new Saml2AuthenticationTokenConverter
				(this.relyingPartyRegistrationResolver);
		when(this.relyingPartyRegistrationResolver.convert(any(HttpServletRequest.class)))
				.thenReturn(this.relyingPartyRegistration);
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setParameter("SAMLResponse", Saml2Utils.samlEncode("response".getBytes(UTF_8)));
		Saml2AuthenticationToken token = converter.convert(request);
		assertThat(token.getSaml2Response()).isEqualTo("response");
		assertThat(token.getRelyingPartyRegistration().getRegistrationId())
				.isEqualTo(relyingPartyRegistration.getRegistrationId());
	}

	@Test
	public void convertWhenNoSamlResponseThenNull() {
		Saml2AuthenticationTokenConverter converter = new Saml2AuthenticationTokenConverter
				(this.relyingPartyRegistrationResolver);
		when(this.relyingPartyRegistrationResolver.convert(any(HttpServletRequest.class)))
				.thenReturn(this.relyingPartyRegistration);
		MockHttpServletRequest request = new MockHttpServletRequest();
		assertThat(converter.convert(request)).isNull();
	}

	@Test
	public void convertWhenNoRelyingPartyRegistrationThenNull() {
		Saml2AuthenticationTokenConverter converter = new Saml2AuthenticationTokenConverter
				(this.relyingPartyRegistrationResolver);
		when(this.relyingPartyRegistrationResolver.convert(any(HttpServletRequest.class)))
				.thenReturn(null);
		MockHttpServletRequest request = new MockHttpServletRequest();
		assertThat(converter.convert(request)).isNull();
	}

	@Test
	public void convertWhenGetRequestThenInflates() {
		Saml2AuthenticationTokenConverter converter = new Saml2AuthenticationTokenConverter
				(this.relyingPartyRegistrationResolver);
		when(this.relyingPartyRegistrationResolver.convert(any(HttpServletRequest.class)))
				.thenReturn(this.relyingPartyRegistration);
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setMethod("GET");
		byte[] deflated = Saml2Utils.samlDeflate("response");
		String encoded = Saml2Utils.samlEncode(deflated);
		request.setParameter("SAMLResponse", encoded);
		Saml2AuthenticationToken token = converter.convert(request);
		assertThat(token.getSaml2Response()).isEqualTo("response");
		assertThat(token.getRelyingPartyRegistration().getRegistrationId())
				.isEqualTo(relyingPartyRegistration.getRegistrationId());
	}

	@Test
	public void constructorWhenResolverIsNullThenIllegalArgument() {
		assertThatCode(() -> new Saml2AuthenticationTokenConverter(null))
				.isInstanceOf(IllegalArgumentException.class);
	}
}
