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

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.oauth2.client.authentication.OAuth2LoginAuthenticationToken;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.OAuth2IntrospectionAuthenticationToken;
import org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;

/**
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 * @since 5.2
 */
public final class OAuth2SecurityMockMvcRequestPostProcessors {
	/**
	 * Establish a {@link SecurityContext} that has a
	 * {@link JwtAuthenticationToken} for the
	 * {@link Authentication} and a {@link Jwt} for the
	 * {@link Authentication#getPrincipal()}. All details are
	 * declarative and do not require the JWT to be valid.
	 *
	 * <p>
	 * The support works by associating the authentication to the HttpServletRequest. To associate
	 * the request to the SecurityContextHolder you need to ensure that the
	 * SecurityContextPersistenceFilter is associated with the MockMvc instance. A few
	 * ways to do this are:
	 * </p>
	 *
	 * <ul>
	 * <li>Invoking apply {@link SecurityMockMvcConfigurers#springSecurity()}</li>
	 * <li>Adding Spring Security's FilterChainProxy to MockMvc</li>
	 * <li>Manually adding {@link SecurityContextPersistenceFilter} to the MockMvc
	 * instance may make sense when using MockMvcBuilders standaloneSetup</li>
	 * </ul>
	 *
	 * @return the {@link JwtRequestPostProcessor} for additional customization
	 */
	public static JwtRequestPostProcessor jwt() {
		return new JwtRequestPostProcessor();
	}

	/**
	 * Establish a {@link SecurityContext} that has a
	 * {@link JwtAuthenticationToken} for the
	 * {@link Authentication} and a {@link Jwt} for the
	 * {@link Authentication#getPrincipal()}. All details are
	 * declarative and do not require the JWT to be valid.
	 *
	 * <p>
	 * The support works by associating the authentication to the HttpServletRequest. To associate
	 * the request to the SecurityContextHolder you need to ensure that the
	 * SecurityContextPersistenceFilter is associated with the MockMvc instance. A few
	 * ways to do this are:
	 * </p>
	 *
	 * <ul>
	 * <li>Invoking apply {@link SecurityMockMvcConfigurers#springSecurity()}</li>
	 * <li>Adding Spring Security's FilterChainProxy to MockMvc</li>
	 * <li>Manually adding {@link SecurityContextPersistenceFilter} to the MockMvc
	 * instance may make sense when using MockMvcBuilders standaloneSetup</li>
	 * </ul>
	 *
	 * @param jwt a complete JWT to extract and apply token value subject, authorities and claims configuration
	 * @return the {@link JwtRequestPostProcessor} for additional customization
	 */
	public static JwtRequestPostProcessor jwt(final Jwt jwt) {
		return jwt().jwt(jwt);
	}

	/**
	 * Establish a {@link SecurityContext} that has an
	 * {@link OAuth2IntrospectionAuthenticationToken} for the
	 * {@link Authentication} and an {@link OAuth2AccessToken} for the
	 * {@link Authentication#getPrincipal()}. All details are
	 * declarative and do not require the OAuth2AccessToken to be valid.
	 *
	 * <p>
	 * The support works by associating the authentication to the HttpServletRequest. To associate
	 * the request to the SecurityContextHolder you need to ensure that the
	 * SecurityContextPersistenceFilter is associated with the MockMvc instance. A few
	 * ways to do this are:
	 * </p>
	 *
	 * <ul>
	 * <li>Invoking apply {@link SecurityMockMvcConfigurers#springSecurity()}</li>
	 * <li>Adding Spring Security's FilterChainProxy to MockMvc</li>
	 * <li>Manually adding {@link SecurityContextPersistenceFilter} to the MockMvc
	 * instance may make sense when using MockMvcBuilders standaloneSetup</li>
	 * </ul>
	 *
	 * @return the {@link AccessTokenRequestPostProcessor} for additional customization
	 */
	public static AccessTokenRequestPostProcessor accessToken() {
		return new AccessTokenRequestPostProcessor();
	}

	/**
	 * Establish a {@link SecurityContext} that has an
	 * {@link OAuth2LoginAuthenticationToken} for the
	 * {@link Authentication} and a {@link DefaultOidcUser} for the
	 * {@link Authentication#getPrincipal()}. All details are
	 * declarative and do not require the DefaultOidcUser to be valid or even user to exist.
	 *
	 * <p>
	 * The support works by associating the authentication to the HttpServletRequest. To associate
	 * the request to the SecurityContextHolder you need to ensure that the
	 * SecurityContextPersistenceFilter is associated with the MockMvc instance. A few
	 * ways to do this are:
	 * </p>
	 *
	 * <ul>
	 * <li>Invoking apply {@link SecurityMockMvcConfigurers#springSecurity()}</li>
	 * <li>Adding Spring Security's FilterChainProxy to MockMvc</li>
	 * <li>Manually adding {@link SecurityContextPersistenceFilter} to the MockMvc
	 * instance may make sense when using MockMvcBuilders standaloneSetup</li>
	 * </ul>
	 *
	 * @param authorizationGrantType authorization request grant-type 
	 * @return the {@link OidcIdTokenRequestPostProcessor} for additional customization
	 */
	public static OidcIdTokenRequestPostProcessor oidcId(final AuthorizationGrantType authorizationGrantType) {
		return new OidcIdTokenRequestPostProcessor(authorizationGrantType);
	}

	/**
	 * Establish a {@link SecurityContext} that has an
	 * {@link OAuth2LoginAuthenticationToken} for the
	 * {@link Authentication} and a {@link DefaultOidcUser} for the
	 * {@link Authentication#getPrincipal()}. All details are
	 * declarative and do not require the DefaultOidcUser to be valid or even user to exist.
	 *
	 * <p>
	 * The support works by associating the authentication to the HttpServletRequest. To associate
	 * the request to the SecurityContextHolder you need to ensure that the
	 * SecurityContextPersistenceFilter is associated with the MockMvc instance. A few
	 * ways to do this are:
	 * </p>
	 *
	 * <ul>
	 * <li>Invoking apply {@link SecurityMockMvcConfigurers#springSecurity()}</li>
	 * <li>Adding Spring Security's FilterChainProxy to MockMvc</li>
	 * <li>Manually adding {@link SecurityContextPersistenceFilter} to the MockMvc
	 * instance may make sense when using MockMvcBuilders standaloneSetup</li>
	 * </ul>
	 *
	 * @return the {@link OidcIdTokenRequestPostProcessor} for additional customization
	 */
	public static OidcIdTokenRequestPostProcessor oidcId() {
		return oidcId(AuthorizationGrantType.AUTHORIZATION_CODE);
	}
}
