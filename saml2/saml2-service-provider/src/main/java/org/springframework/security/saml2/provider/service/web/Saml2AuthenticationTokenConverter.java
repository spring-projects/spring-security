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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.zip.Inflater;
import java.util.zip.InflaterOutputStream;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.codec.binary.Base64;

import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpMethod;
import org.springframework.security.saml2.Saml2Exception;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationToken;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.Assert;

/**
 * An {@link AuthenticationConverter} that generates a {@link Saml2AuthenticationToken}
 * appropriate for authenticated a SAML 2.0 Assertion against an
 * {@link org.springframework.security.authentication.AuthenticationManager}.
 *
 * @author Josh Cummings
 * @since 5.4
 */
public final class Saml2AuthenticationTokenConverter implements AuthenticationConverter {

	private static Base64 BASE64 = new Base64(0, new byte[] { '\n' });

	private final Converter<HttpServletRequest, RelyingPartyRegistration> relyingPartyRegistrationResolver;

	/**
	 * Constructs a {@link Saml2AuthenticationTokenConverter} given a strategy for
	 * resolving {@link RelyingPartyRegistration}s
	 * @param relyingPartyRegistrationResolver the strategy for resolving
	 * {@link RelyingPartyRegistration}s
	 */
	public Saml2AuthenticationTokenConverter(
			Converter<HttpServletRequest, RelyingPartyRegistration> relyingPartyRegistrationResolver) {
		Assert.notNull(relyingPartyRegistrationResolver, "relyingPartyRegistrationResolver cannot be null");
		this.relyingPartyRegistrationResolver = relyingPartyRegistrationResolver;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Saml2AuthenticationToken convert(HttpServletRequest request) {
		RelyingPartyRegistration relyingPartyRegistration = this.relyingPartyRegistrationResolver.convert(request);
		if (relyingPartyRegistration == null) {
			return null;
		}
		String saml2Response = request.getParameter("SAMLResponse");
		if (saml2Response == null) {
			return null;
		}
		byte[] b = samlDecode(saml2Response);
		saml2Response = inflateIfRequired(request, b);
		return new Saml2AuthenticationToken(relyingPartyRegistration, saml2Response);
	}

	private String inflateIfRequired(HttpServletRequest request, byte[] b) {
		if (HttpMethod.GET.matches(request.getMethod())) {
			return samlInflate(b);
		}
		else {
			return new String(b, StandardCharsets.UTF_8);
		}
	}

	private byte[] samlDecode(String s) {
		return BASE64.decode(s);
	}

	private String samlInflate(byte[] b) {
		try {
			ByteArrayOutputStream out = new ByteArrayOutputStream();
			InflaterOutputStream iout = new InflaterOutputStream(out, new Inflater(true));
			iout.write(b);
			iout.finish();
			return new String(out.toByteArray(), StandardCharsets.UTF_8);
		}
		catch (IOException e) {
			throw new Saml2Exception("Unable to inflate string", e);
		}
	}

}
