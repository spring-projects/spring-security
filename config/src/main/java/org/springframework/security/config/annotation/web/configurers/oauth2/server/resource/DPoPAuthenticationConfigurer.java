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

package org.springframework.security.config.annotation.web.configurers.oauth2.server.resource;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationManagerResolver;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.jose.jws.JwsAlgorithms;
import org.springframework.security.oauth2.server.resource.authentication.DPoPAuthenticationProvider;
import org.springframework.security.oauth2.server.resource.authentication.DPoPAuthenticationToken;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationEntryPointFailureHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationFilter;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.context.RequestAttributeSecurityContextRepository;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

/**
 * An {@link AbstractHttpConfigurer} for OAuth 2.0 Demonstrating Proof of Possession
 * (DPoP) support.
 *
 * @author Joe Grandja
 * @since 6.5
 * @see DPoPAuthenticationProvider
 * @see <a target="_blank" href="https://datatracker.ietf.org/doc/html/rfc9449">RFC 9449
 * OAuth 2.0 Demonstrating Proof of Possession (DPoP)</a>
 */
final class DPoPAuthenticationConfigurer<B extends HttpSecurityBuilder<B>>
		extends AbstractHttpConfigurer<DPoPAuthenticationConfigurer<B>, B> {

	private RequestMatcher requestMatcher;

	private AuthenticationConverter authenticationConverter;

	private AuthenticationSuccessHandler authenticationSuccessHandler;

	private AuthenticationFailureHandler authenticationFailureHandler;

	@Override
	public void configure(B http) {
		AuthenticationManager authenticationManager = http.getSharedObject(AuthenticationManager.class);
		http.authenticationProvider(new DPoPAuthenticationProvider(getTokenAuthenticationManager(http)));
		AuthenticationFilter authenticationFilter = new AuthenticationFilter(authenticationManager,
				getAuthenticationConverter());
		authenticationFilter.setRequestMatcher(getRequestMatcher());
		authenticationFilter.setSuccessHandler(getAuthenticationSuccessHandler());
		authenticationFilter.setFailureHandler(getAuthenticationFailureHandler());
		authenticationFilter.setSecurityContextRepository(new RequestAttributeSecurityContextRepository());
		authenticationFilter = postProcess(authenticationFilter);
		http.addFilter(authenticationFilter);
	}

	private AuthenticationManager getTokenAuthenticationManager(B http) {
		OAuth2ResourceServerConfigurer<B> resourceServerConfigurer = http
			.getConfigurer(OAuth2ResourceServerConfigurer.class);
		final AuthenticationManagerResolver<HttpServletRequest> authenticationManagerResolver = resourceServerConfigurer
			.getAuthenticationManagerResolver();
		if (authenticationManagerResolver == null) {
			return resourceServerConfigurer.getAuthenticationManager(http);
		}
		return (authentication) -> {
			RequestAttributes requestAttributes = RequestContextHolder.getRequestAttributes();
			ServletRequestAttributes servletRequestAttributes = (ServletRequestAttributes) requestAttributes;
			AuthenticationManager authenticationManager = authenticationManagerResolver
				.resolve(servletRequestAttributes.getRequest());
			return authenticationManager.authenticate(authentication);
		};
	}

	private RequestMatcher getRequestMatcher() {
		if (this.requestMatcher == null) {
			this.requestMatcher = new DPoPRequestMatcher();
		}
		return this.requestMatcher;
	}

	private AuthenticationConverter getAuthenticationConverter() {
		if (this.authenticationConverter == null) {
			this.authenticationConverter = new DPoPAuthenticationConverter();
		}
		return this.authenticationConverter;
	}

	private AuthenticationSuccessHandler getAuthenticationSuccessHandler() {
		if (this.authenticationSuccessHandler == null) {
			this.authenticationSuccessHandler = (request, response, authentication) -> {
				// No-op - will continue on filter chain
			};
		}
		return this.authenticationSuccessHandler;
	}

	private AuthenticationFailureHandler getAuthenticationFailureHandler() {
		if (this.authenticationFailureHandler == null) {
			this.authenticationFailureHandler = new AuthenticationEntryPointFailureHandler(
					new DPoPAuthenticationEntryPoint());
		}
		return this.authenticationFailureHandler;
	}

	private static final class DPoPRequestMatcher implements RequestMatcher {

		@Override
		public boolean matches(HttpServletRequest request) {
			String authorization = request.getHeader(HttpHeaders.AUTHORIZATION);
			if (!StringUtils.hasText(authorization)) {
				return false;
			}
			return StringUtils.startsWithIgnoreCase(authorization, OAuth2AccessToken.TokenType.DPOP.getValue());
		}

	}

	private static final class DPoPAuthenticationConverter implements AuthenticationConverter {

		private static final Pattern AUTHORIZATION_PATTERN = Pattern.compile("^DPoP (?<token>[a-zA-Z0-9-._~+/]+=*)$",
				Pattern.CASE_INSENSITIVE);

		@Override
		public Authentication convert(HttpServletRequest request) {
			List<String> authorizationList = Collections.list(request.getHeaders(HttpHeaders.AUTHORIZATION));
			if (CollectionUtils.isEmpty(authorizationList)) {
				return null;
			}
			if (authorizationList.size() != 1) {
				OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST,
						"Found multiple Authorization headers.", null);
				throw new OAuth2AuthenticationException(error);
			}
			String authorization = authorizationList.get(0);
			if (!StringUtils.startsWithIgnoreCase(authorization, OAuth2AccessToken.TokenType.DPOP.getValue())) {
				return null;
			}
			Matcher matcher = AUTHORIZATION_PATTERN.matcher(authorization);
			if (!matcher.matches()) {
				OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.INVALID_TOKEN, "DPoP access token is malformed.",
						null);
				throw new OAuth2AuthenticationException(error);
			}
			String accessToken = matcher.group("token");
			List<String> dPoPProofList = Collections
				.list(request.getHeaders(OAuth2AccessToken.TokenType.DPOP.getValue()));
			if (CollectionUtils.isEmpty(dPoPProofList) || dPoPProofList.size() != 1) {
				OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST,
						"DPoP proof is missing or invalid.", null);
				throw new OAuth2AuthenticationException(error);
			}
			String dPoPProof = dPoPProofList.get(0);
			return new DPoPAuthenticationToken(accessToken, dPoPProof, request.getMethod(),
					request.getRequestURL().toString());
		}

	}

	private static final class DPoPAuthenticationEntryPoint implements AuthenticationEntryPoint {

		@Override
		public void commence(HttpServletRequest request, HttpServletResponse response,
				AuthenticationException authenticationException) {
			Map<String, String> parameters = new LinkedHashMap<>();
			if (authenticationException instanceof OAuth2AuthenticationException oauth2AuthenticationException) {
				OAuth2Error error = oauth2AuthenticationException.getError();
				parameters.put(OAuth2ParameterNames.ERROR, error.getErrorCode());
				if (StringUtils.hasText(error.getDescription())) {
					parameters.put(OAuth2ParameterNames.ERROR_DESCRIPTION, error.getDescription());
				}
				if (StringUtils.hasText(error.getUri())) {
					parameters.put(OAuth2ParameterNames.ERROR_URI, error.getUri());
				}
			}
			parameters.put("algs",
					JwsAlgorithms.RS256 + " " + JwsAlgorithms.RS384 + " " + JwsAlgorithms.RS512 + " "
							+ JwsAlgorithms.PS256 + " " + JwsAlgorithms.PS384 + " " + JwsAlgorithms.PS512 + " "
							+ JwsAlgorithms.ES256 + " " + JwsAlgorithms.ES384 + " " + JwsAlgorithms.ES512);
			String wwwAuthenticate = toWWWAuthenticateHeader(parameters);
			response.addHeader(HttpHeaders.WWW_AUTHENTICATE, wwwAuthenticate);
			response.setStatus(HttpStatus.UNAUTHORIZED.value());
		}

		private static String toWWWAuthenticateHeader(Map<String, String> parameters) {
			StringBuilder wwwAuthenticate = new StringBuilder();
			wwwAuthenticate.append(OAuth2AccessToken.TokenType.DPOP.getValue());
			if (!parameters.isEmpty()) {
				wwwAuthenticate.append(" ");
				int i = 0;
				for (Map.Entry<String, String> entry : parameters.entrySet()) {
					wwwAuthenticate.append(entry.getKey()).append("=\"").append(entry.getValue()).append("\"");
					if (i++ != parameters.size() - 1) {
						wwwAuthenticate.append(", ");
					}
				}
			}
			return wwwAuthenticate.toString();
		}

	}

}
