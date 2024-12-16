/*
 * Copyright 2002-2024 the original author or authors.
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

import java.io.IOException;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.core.ResolvableType;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.converter.GenericHttpMessageConverter;
import org.springframework.http.converter.json.Jackson2ObjectMapperBuilder;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.http.server.ServletServerHttpRequest;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.AuthenticationEntryPointFailureHandler;
import org.springframework.security.web.authentication.HttpMessageConverterAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.webauthn.api.AuthenticatorAssertionResponse;
import org.springframework.security.web.webauthn.api.PublicKeyCredential;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialRequestOptions;
import org.springframework.security.web.webauthn.jackson.WebauthnJackson2Module;
import org.springframework.security.web.webauthn.management.RelyingPartyAuthenticationRequest;
import org.springframework.util.Assert;

import static org.springframework.security.web.util.matcher.AntPathRequestMatcher.antMatcher;

/**
 * Authenticates {@code PublicKeyCredential<AuthenticatorAssertionResponse>} that is
 * parsed from the body of the {@link HttpServletRequest} using the
 * {@link #setConverter(GenericHttpMessageConverter)}. An example request is provided
 * below:
 *
 * <pre>
 * {
 * 	"id": "dYF7EGnRFFIXkpXi9XU2wg",
 * 	"rawId": "dYF7EGnRFFIXkpXi9XU2wg",
 * 	"response": {
 * 		"authenticatorData": "y9GqwTRaMpzVDbXq1dyEAXVOxrou08k22ggRC45MKNgdAAAAAA",
 * 		"clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiRFVsRzRDbU9naWhKMG1vdXZFcE9HdUk0ZVJ6MGRRWmxUQmFtbjdHQ1FTNCIsIm9yaWdpbiI6Imh0dHBzOi8vZXhhbXBsZS5sb2NhbGhvc3Q6ODQ0MyIsImNyb3NzT3JpZ2luIjpmYWxzZX0",
 * 		"signature": "MEYCIQCW2BcUkRCAXDmGxwMi78jknenZ7_amWrUJEYoTkweldAIhAMD0EMp1rw2GfwhdrsFIeDsL7tfOXVPwOtfqJntjAo4z",
 * 		"userHandle": "Q3_0Xd64_HW0BlKRAJnVagJTpLKLgARCj8zjugpRnVo"
 * 	    },
 * 	"clientExtensionResults": {},
 * 	"authenticatorAttachment": "platform"
 * }
 * </pre>
 *
 * @author Rob Winch
 * @since 6.4
 */
public class WebAuthnAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

	private GenericHttpMessageConverter<Object> converter = new MappingJackson2HttpMessageConverter(
			Jackson2ObjectMapperBuilder.json().modules(new WebauthnJackson2Module()).build());

	private PublicKeyCredentialRequestOptionsRepository requestOptionsRepository = new HttpSessionPublicKeyCredentialRequestOptionsRepository();

	public WebAuthnAuthenticationFilter() {
		super(antMatcher(HttpMethod.POST, "/login/webauthn"));
		setSecurityContextRepository(new HttpSessionSecurityContextRepository());
		setAuthenticationFailureHandler(
				new AuthenticationEntryPointFailureHandler(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED)));
		setAuthenticationSuccessHandler(new HttpMessageConverterAuthenticationSuccessHandler());
	}

	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException, IOException, ServletException {
		ServletServerHttpRequest httpRequest = new ServletServerHttpRequest(request);
		ResolvableType resolvableType = ResolvableType.forClassWithGenerics(PublicKeyCredential.class,
				AuthenticatorAssertionResponse.class);
		PublicKeyCredential<AuthenticatorAssertionResponse> publicKeyCredential = null;
		try {
			publicKeyCredential = (PublicKeyCredential<AuthenticatorAssertionResponse>) this.converter
				.read(resolvableType.getType(), getClass(), httpRequest);
		}
		catch (Exception ex) {
			throw new BadCredentialsException("Unable to authenticate the PublicKeyCredential", ex);
		}
		PublicKeyCredentialRequestOptions requestOptions = this.requestOptionsRepository.load(request);
		if (requestOptions == null) {
			throw new BadCredentialsException(
					"Unable to authenticate the PublicKeyCredential. No PublicKeyCredentialRequestOptions found.");
		}
		this.requestOptionsRepository.save(request, response, null);
		RelyingPartyAuthenticationRequest authenticationRequest = new RelyingPartyAuthenticationRequest(requestOptions,
				publicKeyCredential);
		WebAuthnAuthenticationRequestToken token = new WebAuthnAuthenticationRequestToken(authenticationRequest);
		return getAuthenticationManager().authenticate(token);
	}

	/**
	 * Sets the {@link GenericHttpMessageConverter} to use for writing
	 * {@code PublicKeyCredential<AuthenticatorAssertionResponse>} to the response. The
	 * default is @{code MappingJackson2HttpMessageConverter}
	 * @param converter the {@link GenericHttpMessageConverter} to use. Cannot be null.
	 */
	public void setConverter(GenericHttpMessageConverter<Object> converter) {
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
