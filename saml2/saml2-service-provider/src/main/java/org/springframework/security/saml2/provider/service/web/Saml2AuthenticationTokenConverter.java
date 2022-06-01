/*
 * Copyright 2002-2022 the original author or authors.
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
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.function.Function;
import java.util.zip.Inflater;
import java.util.zip.InflaterOutputStream;

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.http.HttpMethod;
import org.springframework.security.saml2.core.Saml2Error;
import org.springframework.security.saml2.core.Saml2ErrorCodes;
import org.springframework.security.saml2.core.Saml2ParameterNames;
import org.springframework.security.saml2.provider.service.authentication.AbstractSaml2AuthenticationRequest;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationException;
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

	// MimeDecoder allows extra line-breaks as well as other non-alphabet values.
	// This matches the behaviour of the commons-codec decoder.
	private static final Base64.Decoder BASE64 = Base64.getMimeDecoder();

	private static final Base64Checker BASE_64_CHECKER = new Base64Checker();

	private final RelyingPartyRegistrationResolver relyingPartyRegistrationResolver;

	private Function<HttpServletRequest, AbstractSaml2AuthenticationRequest> loader;

	/**
	 * Constructs a {@link Saml2AuthenticationTokenConverter} given a strategy for
	 * resolving {@link RelyingPartyRegistration}s
	 * @param relyingPartyRegistrationResolver the strategy for resolving
	 * {@link RelyingPartyRegistration}s
	 */
	public Saml2AuthenticationTokenConverter(RelyingPartyRegistrationResolver relyingPartyRegistrationResolver) {
		Assert.notNull(relyingPartyRegistrationResolver, "relyingPartyRegistrationResolver cannot be null");
		this.relyingPartyRegistrationResolver = relyingPartyRegistrationResolver;
		this.loader = new HttpSessionSaml2AuthenticationRequestRepository()::loadAuthenticationRequest;
	}

	@Override
	public Saml2AuthenticationToken convert(HttpServletRequest request) {
		AbstractSaml2AuthenticationRequest authenticationRequest = loadAuthenticationRequest(request);
		String relyingPartyRegistrationId = (authenticationRequest != null)
				? authenticationRequest.getRelyingPartyRegistrationId() : null;
		RelyingPartyRegistration relyingPartyRegistration = this.relyingPartyRegistrationResolver.resolve(request,
				relyingPartyRegistrationId);
		if (relyingPartyRegistration == null) {
			return null;
		}
		String saml2Response = request.getParameter(Saml2ParameterNames.SAML_RESPONSE);
		if (saml2Response == null) {
			return null;
		}
		byte[] b = samlDecode(saml2Response);
		saml2Response = inflateIfRequired(request, b);
		return new Saml2AuthenticationToken(relyingPartyRegistration, saml2Response, authenticationRequest);
	}

	/**
	 * Use the given {@link Saml2AuthenticationRequestRepository} to load authentication
	 * request.
	 * @param authenticationRequestRepository the
	 * {@link Saml2AuthenticationRequestRepository} to use
	 * @since 5.6
	 */
	public void setAuthenticationRequestRepository(
			Saml2AuthenticationRequestRepository<AbstractSaml2AuthenticationRequest> authenticationRequestRepository) {
		Assert.notNull(authenticationRequestRepository, "authenticationRequestRepository cannot be null");
		this.loader = authenticationRequestRepository::loadAuthenticationRequest;
	}

	private AbstractSaml2AuthenticationRequest loadAuthenticationRequest(HttpServletRequest request) {
		return this.loader.apply(request);
	}

	private String inflateIfRequired(HttpServletRequest request, byte[] b) {
		if (HttpMethod.GET.matches(request.getMethod())) {
			return samlInflate(b);
		}
		return new String(b, StandardCharsets.UTF_8);
	}

	private byte[] samlDecode(String base64EncodedPayload) {
		try {
			BASE_64_CHECKER.checkAcceptable(base64EncodedPayload);
			return BASE64.decode(base64EncodedPayload);
		}
		catch (Exception ex) {
			throw new Saml2AuthenticationException(
					new Saml2Error(Saml2ErrorCodes.INVALID_RESPONSE, "Failed to decode SAMLResponse"), ex);
		}
	}

	private String samlInflate(byte[] b) {
		try {
			ByteArrayOutputStream out = new ByteArrayOutputStream();
			InflaterOutputStream inflaterOutputStream = new InflaterOutputStream(out, new Inflater(true));
			inflaterOutputStream.write(b);
			inflaterOutputStream.finish();
			return out.toString(StandardCharsets.UTF_8.name());
		}
		catch (Exception ex) {
			throw new Saml2AuthenticationException(
					new Saml2Error(Saml2ErrorCodes.INVALID_RESPONSE, "Unable to inflate string"), ex);
		}
	}

	static class Base64Checker {

		private static final int[] values = genValueMapping();

		Base64Checker() {

		}

		private static int[] genValueMapping() {
			byte[] alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
					.getBytes(StandardCharsets.ISO_8859_1);

			int[] values = new int[256];
			Arrays.fill(values, -1);
			for (int i = 0; i < alphabet.length; i++) {
				values[alphabet[i] & 0xff] = i;
			}
			return values;
		}

		boolean isAcceptable(String s) {
			int goodChars = 0;
			int lastGoodCharVal = -1;

			// count number of characters from Base64 alphabet
			for (int i = 0; i < s.length(); i++) {
				int val = values[0xff & s.charAt(i)];
				if (val != -1) {
					lastGoodCharVal = val;
					goodChars++;
				}
			}

			// in cases of an incomplete final chunk, ensure the unused bits are zero
			switch (goodChars % 4) {
			case 0:
				return true;
			case 2:
				return (lastGoodCharVal & 0b1111) == 0;
			case 3:
				return (lastGoodCharVal & 0b11) == 0;
			default:
				return false;
			}
		}

		void checkAcceptable(String ins) {
			if (!isAcceptable(ins)) {
				throw new IllegalArgumentException("Unaccepted Encoding");
			}
		}

	}

}
