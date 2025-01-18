/*
 * Copyright 2002-2025 the original author or authors.
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

package org.springframework.security.web.webauthn.registration;

import java.io.IOException;
import java.util.function.Supplier;

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
import org.springframework.security.authorization.AuthenticatedAuthorizationManager;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialCreationOptions;
import org.springframework.security.web.webauthn.jackson.WebauthnJackson2Module;
import org.springframework.security.web.webauthn.management.ImmutablePublicKeyCredentialCreationOptionsRequest;
import org.springframework.security.web.webauthn.management.WebAuthnRelyingPartyOperations;
import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;

import static org.springframework.security.web.util.matcher.AntPathRequestMatcher.antMatcher;

/**
 * A {@link jakarta.servlet.Filter} that renders the
 * {@link PublicKeyCredentialCreationOptions} for <a href=
 * "https://w3c.github.io/webappsec-credential-management/#dom-credentialscontainer-create">creating</a>
 * a new credential.
 *
 * @author DingHao
 */
public class PublicKeyCredentialCreationOptionsFilter extends OncePerRequestFilter {

	private PublicKeyCredentialCreationOptionsRepository repository = new HttpSessionPublicKeyCredentialCreationOptionsRepository();

	private SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder
		.getContextHolderStrategy();

	private RequestMatcher matcher = antMatcher(HttpMethod.POST, "/webauthn/register/options");

	private AuthorizationManager<HttpServletRequest> authorization = AuthenticatedAuthorizationManager.authenticated();

	private final WebAuthnRelyingPartyOperations rpOperations;

	private HttpMessageConverter<Object> converter = new MappingJackson2HttpMessageConverter(
			Jackson2ObjectMapperBuilder.json().modules(new WebauthnJackson2Module()).build());

	/**
	 * Creates a new instance.
	 * @param rpOperations the {@link WebAuthnRelyingPartyOperations} to use. Cannot be
	 * null.
	 */
	public PublicKeyCredentialCreationOptionsFilter(WebAuthnRelyingPartyOperations rpOperations) {
		Assert.notNull(rpOperations, "rpOperations cannot be null");
		this.rpOperations = rpOperations;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		if (!this.matcher.matches(request)) {
			filterChain.doFilter(request, response);
			return;
		}

		Supplier<SecurityContext> context = this.securityContextHolderStrategy.getDeferredContext();
		Supplier<Authentication> authentication = () -> context.get().getAuthentication();
		AuthorizationDecision decision = this.authorization.check(authentication, request);
		if (!decision.isGranted()) {
			response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
			return;
		}
		PublicKeyCredentialCreationOptions options = this.rpOperations.createPublicKeyCredentialCreationOptions(
				new ImmutablePublicKeyCredentialCreationOptionsRequest(authentication.get()));
		this.repository.save(request, response, options);
		response.setStatus(HttpServletResponse.SC_OK);
		response.setHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE);
		this.converter.write(options, MediaType.APPLICATION_JSON, new ServletServerHttpResponse(response));
	}

	/**
	 * Sets the {@link PublicKeyCredentialCreationOptionsRepository} to use. The default
	 * is {@link HttpSessionPublicKeyCredentialCreationOptionsRepository}.
	 * @param creationOptionsRepository the
	 * {@link PublicKeyCredentialCreationOptionsRepository} to use. Cannot be null.
	 */
	public void setCreationOptionsRepository(PublicKeyCredentialCreationOptionsRepository creationOptionsRepository) {
		Assert.notNull(creationOptionsRepository, "creationOptionsRepository cannot be null");
		this.repository = creationOptionsRepository;
	}

	/**
	 * Set the {@link HttpMessageConverter} to read the
	 * {@link WebAuthnRegistrationFilter.WebAuthnRegistrationRequest} and write the
	 * response. The default is {@link MappingJackson2HttpMessageConverter}.
	 * @param converter the {@link HttpMessageConverter} to use. Cannot be null.
	 */
	public void setConverter(HttpMessageConverter<Object> converter) {
		Assert.notNull(converter, "converter cannot be null");
		this.converter = converter;
	}

}
