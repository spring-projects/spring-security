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

package org.springframework.security.web.webauthn.authentication;

import jakarta.servlet.http.HttpServletRequest;
import org.jspecify.annotations.Nullable;

import org.springframework.core.ResolvableType;
import org.springframework.http.converter.SmartHttpMessageConverter;
import org.springframework.http.converter.json.JacksonJsonHttpMessageConverter;
import org.springframework.http.server.ServletServerHttpRequest;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.webauthn.api.AuthenticatorAssertionResponse;
import org.springframework.security.web.webauthn.api.PublicKeyCredential;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialRequestOptions;
import org.springframework.security.web.webauthn.management.RelyingPartyAuthenticationRequest;
import org.springframework.util.Assert;

/**
 * An {@link AuthenticationConverter} that generates a
 * {@link WebAuthnAuthenticationRequestToken} from a WebAuthn authentication request.
 *
 * @author Andrey Litvitski
 * @since 7.1.0
 */
public class WebAuthnAuthenticationConverter implements AuthenticationConverter {

	private SmartHttpMessageConverter<Object> converter;

	private PublicKeyCredentialRequestOptionsRepository requestOptionsRepository;

	/**
	 * Constructs a {@link WebAuthnAuthenticationConverter} given a strategy for reading
	 * the {@code PublicKeyCredential} and loading the
	 * {@code PublicKeyCredentialRequestOptions}.
	 * @param converter the strategy for reading the {@code PublicKeyCredential} from the
	 * request
	 * @param requestOptionsRepository the strategy for loading the
	 * {@code PublicKeyCredentialRequestOptions}
	 */
	public WebAuthnAuthenticationConverter(SmartHttpMessageConverter<Object> converter,
			PublicKeyCredentialRequestOptionsRepository requestOptionsRepository) {
		Assert.notNull(converter, "converter cannot be null");
		Assert.notNull(requestOptionsRepository, "requestOptionsRepository cannot be null");
		this.converter = converter;
		this.requestOptionsRepository = requestOptionsRepository;
	}

	@Override
	public @Nullable WebAuthnAuthenticationRequestToken convert(HttpServletRequest request) {
		ServletServerHttpRequest httpRequest = new ServletServerHttpRequest(request);
		ResolvableType resolvableType = ResolvableType.forClassWithGenerics(PublicKeyCredential.class,
				AuthenticatorAssertionResponse.class);
		PublicKeyCredential<AuthenticatorAssertionResponse> publicKeyCredential;
		try {
			publicKeyCredential = (PublicKeyCredential<AuthenticatorAssertionResponse>) this.converter
				.read(resolvableType, httpRequest, null);
		}
		catch (Exception ex) {
			throw new BadCredentialsException("Unable to authenticate the PublicKeyCredential", ex);
		}
		PublicKeyCredentialRequestOptions requestOptions = this.requestOptionsRepository.load(request);
		if (requestOptions == null) {
			throw new BadCredentialsException(
					"Unable to authenticate the PublicKeyCredential. No PublicKeyCredentialRequestOptions found.");
		}
		RelyingPartyAuthenticationRequest authenticationRequest = new RelyingPartyAuthenticationRequest(requestOptions,
				publicKeyCredential);
		return new WebAuthnAuthenticationRequestToken(authenticationRequest);
	}

	/**
	 * Sets the {@link SmartHttpMessageConverter} to use for reading
	 * {@code PublicKeyCredential<AuthenticatorAssertionResponse>} from the request. The
	 * default is {@link JacksonJsonHttpMessageConverter}.
	 * @param converter the {@link SmartHttpMessageConverter} to use. Cannot be null.
	 * @since 7.0
	 */
	public void setConverter(SmartHttpMessageConverter<Object> converter) {
		Assert.notNull(converter, "converter cannot be null");
		this.converter = converter;
	}

	/**
	 * Sets the {@link PublicKeyCredentialRequestOptionsRepository} to use. The default is
	 * {@link HttpSessionPublicKeyCredentialRequestOptionsRepository}.
	 * @param requestOptionsRepository the
	 * {@link PublicKeyCredentialRequestOptionsRepository} to use. Cannot be null.
	 */
	public void setRequestOptionsRepository(PublicKeyCredentialRequestOptionsRepository requestOptionsRepository) {
		Assert.notNull(requestOptionsRepository, "requestOptionsRepository cannot be null");
		this.requestOptionsRepository = requestOptionsRepository;
	}

}
