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

package org.springframework.security.jackson;

import java.time.Instant;

import tools.jackson.core.Version;
import tools.jackson.databind.cfg.MapperBuilder;
import tools.jackson.databind.jsontype.BasicPolymorphicTypeValidator;
import tools.jackson.databind.jsontype.PolymorphicTypeValidator;
import tools.jackson.databind.module.SimpleModule;

import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.RememberMeAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.core.userdetails.User;

/**
 * Jackson module for spring-security-core. This module register
 * {@link AnonymousAuthenticationTokenMixin}, {@link RememberMeAuthenticationTokenMixin},
 * {@link SimpleGrantedAuthorityMixin}, {{@link UserMixin},
 * {@link UsernamePasswordAuthenticationTokenMixin} and
 * {@link UsernamePasswordAuthenticationTokenMixin}. If no default typing enabled by
 * default then it'll enable it because typing info is needed to properly
 * serialize/deserialize objects. In order to use this module just add this module into
 * your JsonMapper configuration.
 *
 * <pre>
 *     JsonMapper mapper = JsonMapper.builder()
 * 				.addModule(new CoreJacksonModule())
 * 				.build();
 * </pre>
 *
 * <b>Note: use {@link SecurityJacksonModules#getModules(ClassLoader)} to get list of all
 * security modules.</b>
 *
 * @author Sebastien Deleuze
 * @author Jitendra Singh
 * @since 7.O
 * @see SecurityJacksonModules
 */
@SuppressWarnings("serial")
public class CoreJacksonModule extends SimpleModule {

	public CoreJacksonModule() {
		super(CoreJacksonModule.class.getName(), new Version(1, 0, 0, null, null, null));
	}

	@Override
	public void setupModule(SetupContext context) {
		PolymorphicTypeValidator ptv = BasicPolymorphicTypeValidator.builder()
			.allowIfSubType(Instant.class)
			// TODO Check if really necessary
			.allowIfSubType("java.util.Collections$UnmodifiableSet")
			.allowIfBaseType(GrantedAuthority.class)
			.allowIfBaseType(Authentication.class)
			.allowIfSubType(User.class)
			.allowIfSubType(BadCredentialsException.class)
			.allowIfSubType(SecurityContextImpl.class)
			// TODO Move to the proper cas module
			.allowIfSubType("org.apereo.cas.client.validation.AssertionImpl")
			.allowIfSubType("org.apereo.cas.client.authentication.AttributePrincipalImpl")
			// TODO Move to the proper ldap module
			.allowIfSubType("org.springframework.security.ldap.userdetails.InetOrgPerson")
			.allowIfSubType("org.springframework.security.ldap.userdetails.LdapUserDetailsImpl")
			.allowIfSubType("org.springframework.security.ldap.userdetails.Person")
			// TODO Move to the proper oauth2-client module
			.allowIfSubType("org.springframework.security.oauth2.core.OAuth2AuthenticationException")
			.allowIfSubType("org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser")
			.allowIfSubType("org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest")
			.allowIfSubType("org.springframework.security.oauth2.core.OAuth2Error")
			.allowIfSubType("org.springframework.security.oauth2.client.OAuth2AuthorizedClient")
			.allowIfSubType("org.springframework.security.oauth2.core.oidc.OidcIdToken")
			.allowIfSubType("org.springframework.security.oauth2.core.oidc.OidcUserInfo")
			.allowIfSubType("org.springframework.security.oauth2.core.user.DefaultOAuth2User")
			.allowIfSubType("org.springframework.security.oauth2.client.registration.ClientRegistration")
			.allowIfSubType("org.springframework.security.oauth2.core.OAuth2AccessToken")
			.allowIfSubType("org.springframework.security.oauth2.core.OAuth2RefreshToken")
			// TODO Move to the proper saml2-service-provider module
			.allowIfSubType("org.springframework.security.saml2.provider.service.authentication.Saml2ResponseAssertion")
			.allowIfSubType(
					"org.springframework.security.saml2.provider.service.authentication.DefaultSaml2AuthenticatedPrincipal")
			.allowIfSubType(
					"org.springframework.security.saml2.provider.service.authentication.Saml2PostAuthenticationRequest")
			.allowIfSubType(
					"org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutRequest")
			.allowIfSubType(
					"org.springframework.security.saml2.provider.service.authentication.Saml2RedirectAuthenticationRequest")
			.allowIfSubType(
					"org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationException")
			.allowIfSubType("org.springframework.security.saml2.core.Saml2Error")
			// TODO Move to the proper web module
			.allowIfSubType("jakarta.servlet.http.Cookie")
			.allowIfSubType("org.springframework.security.web.csrf.DefaultCsrfToken")
			.allowIfSubType("org.springframework.security.web.savedrequest.DefaultSavedRequest")
			.allowIfSubType("org.springframework.security.web.savedrequest.SavedCookie")
			.allowIfSubType("org.springframework.security.web.authentication.WebAuthenticationDetails")
			.allowIfSubType("org.springframework.security.web.server.csrf.DefaultCsrfToken")
			.build();
		((MapperBuilder<?, ?>) context.getOwner()).polymorphicTypeValidator(ptv);
		context.setMixIn(AnonymousAuthenticationToken.class, AnonymousAuthenticationTokenMixin.class);
		context.setMixIn(RememberMeAuthenticationToken.class, RememberMeAuthenticationTokenMixin.class);
		context.setMixIn(SimpleGrantedAuthority.class, SimpleGrantedAuthorityMixin.class);
		context.setMixIn(User.class, UserMixin.class);
		context.setMixIn(UsernamePasswordAuthenticationToken.class, UsernamePasswordAuthenticationTokenMixin.class);
		context.setMixIn(BadCredentialsException.class, BadCredentialsExceptionMixin.class);
		context.setMixIn(SecurityContextImpl.class, SecurityContextImplMixin.class);
	}

}
