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

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.json.Jackson2ObjectMapperBuilder;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialRequestOptions;
import org.springframework.security.web.webauthn.jackson.WebauthnJackson2Module;
import org.springframework.security.web.webauthn.management.ImmutablePublicKeyCredentialRequestOptionsRequest;
import org.springframework.security.web.webauthn.management.WebAuthnRelyingPartyOperations;
import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;

import static org.springframework.security.web.util.matcher.AntPathRequestMatcher.antMatcher;

/**
 * A {@link jakarta.servlet.Filter} that renders the
 * {@link PublicKeyCredentialRequestOptions} in order to <a href=
 * "https://w3c.github.io/webappsec-credential-management/#dom-credentialscontainer-get">get</a>
 * a credential.
 *
 * @author Rob Winch
 * @since 6.4
 */
public class PublicKeyCredentialRequestOptionsFilter extends OncePerRequestFilter {

	private RequestMatcher matcher = antMatcher(HttpMethod.POST, "/webauthn/authenticate/options");

	private SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder
		.getContextHolderStrategy();

	private final WebAuthnRelyingPartyOperations rpOptions;

	private PublicKeyCredentialRequestOptionsRepository requestOptionsRepository = new HttpSessionPublicKeyCredentialRequestOptionsRepository();

	private HttpMessageConverter<Object> converter = new MappingJackson2HttpMessageConverter(
			Jackson2ObjectMapperBuilder.json().modules(new WebauthnJackson2Module()).build());

	/**
	 * Creates a new instance with the provided {@link WebAuthnRelyingPartyOperations}.
	 * @param rpOptions the {@link WebAuthnRelyingPartyOperations} to use. Cannot be null.
	 */
	public PublicKeyCredentialRequestOptionsFilter(WebAuthnRelyingPartyOperations rpOptions) {
		Assert.notNull(rpOptions, "rpOperations cannot be null");
		this.rpOptions = rpOptions;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		if (!this.matcher.matches(request)) {
			filterChain.doFilter(request, response);
			return;
		}

		SecurityContext context = this.securityContextHolderStrategy.getContext();
		ImmutablePublicKeyCredentialRequestOptionsRequest optionsRequest = new ImmutablePublicKeyCredentialRequestOptionsRequest(
				context.getAuthentication());
		PublicKeyCredentialRequestOptions credentialRequestOptions = this.rpOptions
			.createCredentialRequestOptions(optionsRequest);
		this.requestOptionsRepository.save(request, response, credentialRequestOptions);
		response.setHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE);
		this.converter.write(credentialRequestOptions, MediaType.APPLICATION_JSON,
				new ServletServerHttpResponse(response));

	}

	/**
	 * Sets the {@link PublicKeyCredentialRequestOptionsRepository} to use.
	 * @param requestOptionsRepository the
	 * {@link PublicKeyCredentialRequestOptionsRepository} to use. Cannot be null.
	 */
	public void setRequestOptionsRepository(PublicKeyCredentialRequestOptionsRepository requestOptionsRepository) {
		Assert.notNull(requestOptionsRepository, "requestOptionsRepository cannot be null");
		this.requestOptionsRepository = requestOptionsRepository;
	}

	/**
	 * Sets the {@link HttpMessageConverter} to use.
	 * @param converter the {@link HttpMessageConverter} to use. Cannot be null.
	 */
	public void setConverter(HttpMessageConverter<Object> converter) {
		Assert.notNull(converter, "converter cannot be null");
		this.converter = converter;
	}

	/**
	 * Sets the {@link SecurityContextHolderStrategy} to use.
	 * @param securityContextHolderStrategy the {@link SecurityContextHolderStrategy} to
	 * use. Cannot be null.
	 */
	public void setSecurityContextHolderStrategy(SecurityContextHolderStrategy securityContextHolderStrategy) {
		Assert.notNull(securityContextHolderStrategy, "securityContextHolderStrategy cannot be null");
		this.securityContextHolderStrategy = securityContextHolderStrategy;
	}

}
