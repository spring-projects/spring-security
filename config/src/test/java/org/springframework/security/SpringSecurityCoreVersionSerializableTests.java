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

package org.springframework.security;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.NotSerializableException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.ObjectStreamClass;
import java.io.Serializable;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.apereo.cas.client.validation.AssertionImpl;
import org.instancio.Instancio;
import org.instancio.InstancioApi;
import org.instancio.Select;
import org.instancio.generator.Generator;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.context.annotation.ClassPathScanningCandidateComponentProvider;
import org.springframework.core.type.filter.AssignableTypeFilter;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.AuthorizationServiceException;
import org.springframework.security.access.intercept.RunAsUserToken;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AccountExpiredException;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.ProviderNotFoundException;
import org.springframework.security.authentication.RememberMeAuthenticationToken;
import org.springframework.security.authentication.TestAuthentication;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.event.AuthenticationFailureBadCredentialsEvent;
import org.springframework.security.authentication.event.AuthenticationFailureCredentialsExpiredEvent;
import org.springframework.security.authentication.event.AuthenticationFailureDisabledEvent;
import org.springframework.security.authentication.event.AuthenticationFailureExpiredEvent;
import org.springframework.security.authentication.event.AuthenticationFailureLockedEvent;
import org.springframework.security.authentication.event.AuthenticationFailureProviderNotFoundEvent;
import org.springframework.security.authentication.event.AuthenticationFailureProxyUntrustedEvent;
import org.springframework.security.authentication.event.AuthenticationFailureServiceExceptionEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.authentication.event.InteractiveAuthenticationSuccessEvent;
import org.springframework.security.authentication.event.LogoutSuccessEvent;
import org.springframework.security.authentication.jaas.JaasAuthenticationToken;
import org.springframework.security.authentication.jaas.event.JaasAuthenticationFailedEvent;
import org.springframework.security.authentication.jaas.event.JaasAuthenticationSuccessEvent;
import org.springframework.security.authentication.ott.InvalidOneTimeTokenException;
import org.springframework.security.authentication.ott.OneTimeTokenAuthenticationToken;
import org.springframework.security.authentication.password.CompromisedPasswordException;
import org.springframework.security.cas.authentication.CasAssertionAuthenticationToken;
import org.springframework.security.cas.authentication.CasAuthenticationToken;
import org.springframework.security.cas.authentication.CasServiceTicketAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.SpringSecurityCoreVersion;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.core.session.AbstractSessionEvent;
import org.springframework.security.core.session.ReactiveSessionInformation;
import org.springframework.security.core.session.SessionInformation;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.ldap.ppolicy.PasswordPolicyErrorStatus;
import org.springframework.security.ldap.ppolicy.PasswordPolicyException;
import org.springframework.security.ldap.userdetails.LdapAuthority;
import org.springframework.security.oauth2.client.ClientAuthorizationException;
import org.springframework.security.oauth2.client.ClientAuthorizationRequiredException;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthorizationCodeAuthenticationToken;
import org.springframework.security.oauth2.client.authentication.OAuth2LoginAuthenticationToken;
import org.springframework.security.oauth2.client.authentication.TestOAuth2AuthenticationTokens;
import org.springframework.security.oauth2.client.authentication.TestOAuth2AuthorizationCodeAuthenticationTokens;
import org.springframework.security.oauth2.client.oidc.authentication.logout.OidcLogoutToken;
import org.springframework.security.oauth2.client.oidc.authentication.logout.TestOidcLogoutTokens;
import org.springframework.security.oauth2.client.oidc.session.OidcSessionInformation;
import org.springframework.security.oauth2.client.oidc.session.TestOidcSessionInformations;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.TestClientRegistrations;
import org.springframework.security.oauth2.core.DefaultOAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.OAuth2DeviceCode;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.OAuth2UserCode;
import org.springframework.security.oauth2.core.TestOAuth2AccessTokens;
import org.springframework.security.oauth2.core.TestOAuth2AuthenticatedPrincipals;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationExchange;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponse;
import org.springframework.security.oauth2.core.endpoint.TestOAuth2AuthorizationExchanges;
import org.springframework.security.oauth2.core.endpoint.TestOAuth2AuthorizationRequests;
import org.springframework.security.oauth2.core.endpoint.TestOAuth2AuthorizationResponses;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.TestOidcIdTokens;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;
import org.springframework.security.oauth2.core.oidc.user.TestOidcUsers;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2UserAuthority;
import org.springframework.security.oauth2.core.user.TestOAuth2Users;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoderInitializationException;
import org.springframework.security.oauth2.jwt.JwtEncodingException;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.JwtValidationException;
import org.springframework.security.oauth2.jwt.TestJwts;
import org.springframework.security.oauth2.server.resource.BearerTokenError;
import org.springframework.security.oauth2.server.resource.BearerTokenErrors;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthentication;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.introspection.BadOpaqueTokenException;
import org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionAuthenticatedPrincipal;
import org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionException;
import org.springframework.security.saml2.Saml2Exception;
import org.springframework.security.saml2.core.Saml2Error;
import org.springframework.security.saml2.provider.service.authentication.DefaultSaml2AuthenticatedPrincipal;
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationException;
import org.springframework.security.saml2.provider.service.authentication.Saml2PostAuthenticationRequest;
import org.springframework.security.saml2.provider.service.authentication.Saml2RedirectAuthenticationRequest;
import org.springframework.security.saml2.provider.service.authentication.TestSaml2Authentications;
import org.springframework.security.saml2.provider.service.authentication.TestSaml2PostAuthenticationRequests;
import org.springframework.security.saml2.provider.service.authentication.TestSaml2RedirectAuthenticationRequests;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedCredentialsNotFoundException;
import org.springframework.security.web.authentication.rememberme.CookieTheftException;
import org.springframework.security.web.authentication.rememberme.InvalidCookieException;
import org.springframework.security.web.authentication.rememberme.RememberMeAuthenticationException;
import org.springframework.security.web.authentication.session.SessionAuthenticationException;
import org.springframework.security.web.authentication.session.SessionFixationProtectionEvent;
import org.springframework.security.web.authentication.switchuser.AuthenticationSwitchUserEvent;
import org.springframework.security.web.authentication.www.NonceExpiredException;
import org.springframework.security.web.csrf.CsrfException;
import org.springframework.security.web.csrf.DefaultCsrfToken;
import org.springframework.security.web.csrf.InvalidCsrfTokenException;
import org.springframework.security.web.csrf.MissingCsrfTokenException;
import org.springframework.security.web.firewall.RequestRejectedException;
import org.springframework.security.web.server.firewall.ServerExchangeRejectedException;
import org.springframework.security.web.session.HttpSessionCreatedEvent;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;

/**
 * Tests that Spring Security classes that implements {@link Serializable} and have the
 * same serial version as {@link SpringSecurityCoreVersion#SERIAL_VERSION_UID} can be
 * deserialized from a previous minor version.
 * <p>
 * For example, all classes from version 6.2.x that matches the previous requirement
 * should be serialized and saved to a folder, and then later on, in 6.3.x, it is verified
 * if they can be deserialized
 *
 * @author Marcus da Coregio
 * @since 6.2.2
 * @see <a href="https://github.com/spring-projects/spring-security/issues/3737">GitHub
 * Issue #3737</a>
 */
class SpringSecurityCoreVersionSerializableTests {

	private static final Map<Class<?>, Generator<?>> generatorByClassName = new HashMap<>();

	static final long securitySerialVersionUid = SpringSecurityCoreVersion.SERIAL_VERSION_UID;

	static Path currentVersionFolder = Paths.get("src/test/resources/serialized/" + getCurrentVersion());

	static Path previousVersionFolder = Paths.get("src/test/resources/serialized/" + getPreviousVersion());

	static {
		UserDetails user = TestAuthentication.user();
		Authentication authentication = TestAuthentication.authenticated(user);
		SecurityContext securityContext = new SecurityContextImpl(authentication);

		// oauth2-core
		generatorByClassName.put(DefaultOAuth2User.class, (r) -> TestOAuth2Users.create());
		generatorByClassName.put(OAuth2AuthorizationRequest.class,
				(r) -> TestOAuth2AuthorizationRequests.request().build());
		generatorByClassName.put(OAuth2AuthorizationResponse.class,
				(r) -> TestOAuth2AuthorizationResponses.success().build());
		generatorByClassName.put(OAuth2UserAuthority.class, (r) -> new OAuth2UserAuthority(Map.of("username", "user")));
		generatorByClassName.put(OAuth2AuthorizationExchange.class, (r) -> TestOAuth2AuthorizationExchanges.success());
		generatorByClassName.put(OidcUserInfo.class, (r) -> OidcUserInfo.builder().email("email@example.com").build());
		generatorByClassName.put(SessionInformation.class,
				(r) -> new SessionInformation(user, r.alphanumeric(4), new Date(1704378933936L)));
		generatorByClassName.put(ReactiveSessionInformation.class,
				(r) -> new ReactiveSessionInformation(user, r.alphanumeric(4), Instant.ofEpochMilli(1704378933936L)));
		generatorByClassName.put(OAuth2AccessToken.class, (r) -> TestOAuth2AccessTokens.scopes("scope"));
		generatorByClassName.put(OAuth2DeviceCode.class,
				(r) -> new OAuth2DeviceCode("token", Instant.now(), Instant.now()));
		generatorByClassName.put(OAuth2RefreshToken.class,
				(r) -> new OAuth2RefreshToken("refreshToken", Instant.now(), Instant.now()));
		generatorByClassName.put(OAuth2UserCode.class,
				(r) -> new OAuth2UserCode("token", Instant.now(), Instant.now()));
		generatorByClassName.put(DefaultOidcUser.class, (r) -> TestOidcUsers.create());
		generatorByClassName.put(OidcUserAuthority.class,
				(r) -> new OidcUserAuthority(TestOidcIdTokens.idToken().build(),
						new OidcUserInfo(Map.of("claim", "value")), "claim"));
		generatorByClassName.put(OAuth2AuthenticationException.class,
				(r) -> new OAuth2AuthenticationException(new OAuth2Error("error", "description", "uri"), "message",
						new RuntimeException()));
		generatorByClassName.put(OAuth2AuthorizationException.class,
				(r) -> new OAuth2AuthorizationException(new OAuth2Error("error", "description", "uri"), "message",
						new RuntimeException()));

		// oauth2-client
		ClientRegistration.Builder clientRegistrationBuilder = TestClientRegistrations.clientRegistration();
		ClientRegistration clientRegistration = clientRegistrationBuilder.build();
		WebAuthenticationDetails details = new WebAuthenticationDetails("remote", "sessionId");
		generatorByClassName.put(ClientRegistration.class, (r) -> clientRegistration);
		generatorByClassName.put(ClientRegistration.ProviderDetails.class,
				(r) -> clientRegistration.getProviderDetails());
		generatorByClassName.put(ClientRegistration.ProviderDetails.UserInfoEndpoint.class,
				(r) -> clientRegistration.getProviderDetails().getUserInfoEndpoint());
		generatorByClassName.put(ClientRegistration.Builder.class, (r) -> clientRegistrationBuilder);
		generatorByClassName.put(OAuth2AuthorizedClient.class,
				(r) -> new OAuth2AuthorizedClient(clientRegistration, "principal", TestOAuth2AccessTokens.noScopes()));
		generatorByClassName.put(OAuth2LoginAuthenticationToken.class, (r) -> {
			var token = new OAuth2LoginAuthenticationToken(clientRegistration,
					TestOAuth2AuthorizationExchanges.success());
			token.setDetails(details);
			return token;
		});
		generatorByClassName.put(OAuth2AuthorizationCodeAuthenticationToken.class, (r) -> {
			var token = TestOAuth2AuthorizationCodeAuthenticationTokens.authenticated();
			token.setDetails(details);
			return token;
		});
		generatorByClassName.put(OAuth2AuthenticationToken.class, (r) -> {
			var token = TestOAuth2AuthenticationTokens.authenticated();
			token.setDetails(details);
			return token;
		});
		generatorByClassName.put(OidcIdToken.class, (r) -> TestOidcIdTokens.idToken().build());
		generatorByClassName.put(OidcLogoutToken.class,
				(r) -> TestOidcLogoutTokens.withSessionId("issuer", "sessionId").issuedAt(Instant.now()).build());
		generatorByClassName.put(OidcSessionInformation.class, (r) -> TestOidcSessionInformations.create());
		generatorByClassName.put(DefaultOAuth2AuthenticatedPrincipal.class, (r) -> {
			OAuth2AuthenticatedPrincipal principal = TestOAuth2AuthenticatedPrincipals.active();
			return new DefaultOAuth2AuthenticatedPrincipal(principal.getName(), principal.getAttributes(),
					(Collection<GrantedAuthority>) principal.getAuthorities());
		});
		generatorByClassName.put(ClientAuthorizationException.class,
				(r) -> new ClientAuthorizationException(new OAuth2Error("error", "description", "uri"), "id", "message",
						new RuntimeException()));
		generatorByClassName.put(ClientAuthorizationRequiredException.class,
				(r) -> new ClientAuthorizationRequiredException("id"));

		// oauth2-jose
		generatorByClassName.put(BadJwtException.class, (r) -> new BadJwtException("token", new RuntimeException()));
		generatorByClassName.put(JwtDecoderInitializationException.class,
				(r) -> new JwtDecoderInitializationException("message", new RuntimeException()));
		generatorByClassName.put(JwtEncodingException.class,
				(r) -> new JwtEncodingException("message", new RuntimeException()));
		generatorByClassName.put(JwtException.class, (r) -> new JwtException("message", new RuntimeException()));
		generatorByClassName.put(JwtValidationException.class,
				(r) -> new JwtValidationException("message", List.of(new OAuth2Error("error", "description", "uri"))));

		// oauth2-jwt
		generatorByClassName.put(Jwt.class, (r) -> TestJwts.user());

		// oauth2-resource-server
		generatorByClassName
			.put(org.springframework.security.oauth2.server.resource.BearerTokenAuthenticationToken.class, (r) -> {
				var token = new org.springframework.security.oauth2.server.resource.BearerTokenAuthenticationToken(
						"token");
				token.setDetails(details);
				return token;
			});
		generatorByClassName.put(BearerTokenAuthenticationToken.class, (r) -> {
			var token = new BearerTokenAuthenticationToken("token");
			token.setDetails(details);
			return token;
		});
		generatorByClassName.put(BearerTokenAuthentication.class, (r) -> {
			var token = new BearerTokenAuthentication(TestOAuth2AuthenticatedPrincipals.active(),
					TestOAuth2AccessTokens.noScopes(), user.getAuthorities());
			token.setDetails(details);
			return token;
		});
		generatorByClassName.put(JwtAuthenticationToken.class, (r) -> {
			var token = new JwtAuthenticationToken(TestJwts.user());
			token.setDetails(details);
			return token;
		});
		generatorByClassName.put(BearerTokenError.class, (r) -> BearerTokenErrors.invalidToken("invalid token"));
		generatorByClassName.put(OAuth2IntrospectionAuthenticatedPrincipal.class,
				(r) -> TestOAuth2AuthenticatedPrincipals.active());
		generatorByClassName.put(InvalidBearerTokenException.class,
				(r) -> new InvalidBearerTokenException("description", new RuntimeException()));
		generatorByClassName.put(BadOpaqueTokenException.class,
				(r) -> new BadOpaqueTokenException("message", new RuntimeException()));
		generatorByClassName.put(OAuth2IntrospectionException.class,
				(r) -> new OAuth2IntrospectionException("message", new RuntimeException()));

		// core
		generatorByClassName.put(RunAsUserToken.class, (r) -> {
			RunAsUserToken token = new RunAsUserToken("key", user, "creds", user.getAuthorities(),
					AnonymousAuthenticationToken.class);
			token.setDetails(details);
			return token;
		});
		generatorByClassName.put(RememberMeAuthenticationToken.class, (r) -> {
			RememberMeAuthenticationToken token = new RememberMeAuthenticationToken("key", user, user.getAuthorities());
			token.setDetails(details);
			return token;
		});
		generatorByClassName.put(UsernamePasswordAuthenticationToken.class, (r) -> {
			var token = UsernamePasswordAuthenticationToken.unauthenticated(user, "creds");
			token.setDetails(details);
			return token;
		});
		generatorByClassName.put(JaasAuthenticationToken.class, (r) -> {
			var token = new JaasAuthenticationToken(user, "creds", null);
			token.setDetails(details);
			return token;
		});
		generatorByClassName.put(OneTimeTokenAuthenticationToken.class,
				(r) -> applyDetails(new OneTimeTokenAuthenticationToken("username", "token")));
		generatorByClassName.put(AccessDeniedException.class,
				(r) -> new AccessDeniedException("access denied", new RuntimeException()));
		generatorByClassName.put(AuthorizationServiceException.class,
				(r) -> new AuthorizationServiceException("access denied", new RuntimeException()));
		generatorByClassName.put(AccountExpiredException.class,
				(r) -> new AccountExpiredException("error", new RuntimeException()));
		generatorByClassName.put(AuthenticationCredentialsNotFoundException.class,
				(r) -> new AuthenticationCredentialsNotFoundException("error", new RuntimeException()));
		generatorByClassName.put(AuthenticationServiceException.class,
				(r) -> new AuthenticationServiceException("error", new RuntimeException()));
		generatorByClassName.put(BadCredentialsException.class,
				(r) -> new BadCredentialsException("error", new RuntimeException()));
		generatorByClassName.put(CredentialsExpiredException.class,
				(r) -> new CredentialsExpiredException("error", new RuntimeException()));
		generatorByClassName.put(DisabledException.class,
				(r) -> new DisabledException("error", new RuntimeException()));
		generatorByClassName.put(InsufficientAuthenticationException.class,
				(r) -> new InsufficientAuthenticationException("error", new RuntimeException()));
		generatorByClassName.put(InternalAuthenticationServiceException.class,
				(r) -> new InternalAuthenticationServiceException("error", new RuntimeException()));
		generatorByClassName.put(LockedException.class, (r) -> new LockedException("error", new RuntimeException()));
		generatorByClassName.put(ProviderNotFoundException.class, (r) -> new ProviderNotFoundException("error"));
		generatorByClassName.put(InvalidOneTimeTokenException.class, (r) -> new InvalidOneTimeTokenException("error"));
		generatorByClassName.put(CompromisedPasswordException.class,
				(r) -> new CompromisedPasswordException("error", new RuntimeException()));
		generatorByClassName.put(UsernameNotFoundException.class,
				(r) -> new UsernameNotFoundException("error", new RuntimeException()));
		generatorByClassName.put(TestingAuthenticationToken.class,
				(r) -> applyDetails(new TestingAuthenticationToken("username", "password")));
		generatorByClassName.put(AuthenticationFailureBadCredentialsEvent.class,
				(r) -> new AuthenticationFailureBadCredentialsEvent(authentication,
						new BadCredentialsException("message")));
		generatorByClassName.put(AuthenticationFailureCredentialsExpiredEvent.class,
				(r) -> new AuthenticationFailureCredentialsExpiredEvent(authentication,
						new CredentialsExpiredException("message")));
		generatorByClassName.put(AuthenticationFailureDisabledEvent.class,
				(r) -> new AuthenticationFailureDisabledEvent(authentication, new DisabledException("message")));
		generatorByClassName.put(AuthenticationFailureExpiredEvent.class,
				(r) -> new AuthenticationFailureExpiredEvent(authentication, new AccountExpiredException("message")));
		generatorByClassName.put(AuthenticationFailureLockedEvent.class,
				(r) -> new AuthenticationFailureLockedEvent(authentication, new LockedException("message")));
		generatorByClassName.put(AuthenticationFailureProviderNotFoundEvent.class,
				(r) -> new AuthenticationFailureProviderNotFoundEvent(authentication,
						new ProviderNotFoundException("message")));
		generatorByClassName.put(AuthenticationFailureProxyUntrustedEvent.class,
				(r) -> new AuthenticationFailureProxyUntrustedEvent(authentication,
						new AuthenticationServiceException("message")));
		generatorByClassName.put(AuthenticationFailureServiceExceptionEvent.class,
				(r) -> new AuthenticationFailureServiceExceptionEvent(authentication,
						new AuthenticationServiceException("message")));
		generatorByClassName.put(AuthenticationSuccessEvent.class,
				(r) -> new AuthenticationSuccessEvent(authentication));
		generatorByClassName.put(InteractiveAuthenticationSuccessEvent.class,
				(r) -> new InteractiveAuthenticationSuccessEvent(authentication, Authentication.class));
		generatorByClassName.put(LogoutSuccessEvent.class, (r) -> new LogoutSuccessEvent(authentication));
		generatorByClassName.put(JaasAuthenticationFailedEvent.class,
				(r) -> new JaasAuthenticationFailedEvent(authentication, new RuntimeException("message")));
		generatorByClassName.put(JaasAuthenticationSuccessEvent.class,
				(r) -> new JaasAuthenticationSuccessEvent(authentication));
		generatorByClassName.put(AbstractSessionEvent.class, (r) -> new AbstractSessionEvent(securityContext));

		// cas
		generatorByClassName.put(CasServiceTicketAuthenticationToken.class, (r) -> {
			CasServiceTicketAuthenticationToken token = CasServiceTicketAuthenticationToken.stateless("creds");
			token.setDetails(details);
			return token;
		});
		generatorByClassName.put(CasAuthenticationToken.class, (r) -> {
			var token = new CasAuthenticationToken("key", user, "Password", user.getAuthorities(), user,
					new AssertionImpl("test"));
			token.setDetails(details);
			return token;
		});
		generatorByClassName.put(CasAssertionAuthenticationToken.class, (r) -> {
			var token = new CasAssertionAuthenticationToken(new AssertionImpl("test"), "ticket");
			token.setDetails(details);
			return token;
		});

		// ldap
		generatorByClassName.put(LdapAuthority.class,
				(r) -> new LdapAuthority("USER", "username", Map.of("attribute", List.of("value1", "value2"))));
		generatorByClassName.put(PasswordPolicyException.class,
				(r) -> new PasswordPolicyException(PasswordPolicyErrorStatus.INSUFFICIENT_PASSWORD_QUALITY));

		// saml2-service-provider
		generatorByClassName.put(Saml2AuthenticationException.class,
				(r) -> new Saml2AuthenticationException(new Saml2Error("code", "descirption"), "message",
						new IOException("fail")));
		generatorByClassName.put(Saml2Exception.class, (r) -> new Saml2Exception("message", new IOException("fail")));
		generatorByClassName.put(DefaultSaml2AuthenticatedPrincipal.class,
				(r) -> TestSaml2Authentications.authentication().getPrincipal());
		generatorByClassName.put(Saml2Authentication.class,
				(r) -> applyDetails(TestSaml2Authentications.authentication()));
		generatorByClassName.put(Saml2PostAuthenticationRequest.class,
				(r) -> TestSaml2PostAuthenticationRequests.create());
		generatorByClassName.put(Saml2RedirectAuthenticationRequest.class,
				(r) -> TestSaml2RedirectAuthenticationRequests.create());

		// web
		generatorByClassName.put(AnonymousAuthenticationToken.class, (r) -> {
			Collection<GrantedAuthority> authorities = AuthorityUtils.createAuthorityList("ROLE_USER");
			return applyDetails(new AnonymousAuthenticationToken("key", "username", authorities));
		});
		generatorByClassName.put(PreAuthenticatedAuthenticationToken.class, (r) -> {
			PreAuthenticatedAuthenticationToken token = new PreAuthenticatedAuthenticationToken(user, "creds",
					user.getAuthorities());
			token.setDetails(details);
			return token;
		});
		generatorByClassName.put(PreAuthenticatedCredentialsNotFoundException.class,
				(r) -> new PreAuthenticatedCredentialsNotFoundException("message", new IOException("fail")));
		generatorByClassName.put(CookieTheftException.class, (r) -> new CookieTheftException("message"));
		generatorByClassName.put(InvalidCookieException.class, (r) -> new InvalidCookieException("message"));
		generatorByClassName.put(RememberMeAuthenticationException.class,
				(r) -> new RememberMeAuthenticationException("message", new IOException("fail")));
		generatorByClassName.put(SessionAuthenticationException.class,
				(r) -> new SessionAuthenticationException("message"));
		generatorByClassName.put(NonceExpiredException.class,
				(r) -> new NonceExpiredException("message", new IOException("fail")));
		generatorByClassName.put(CsrfException.class, (r) -> new CsrfException("message"));
		generatorByClassName.put(org.springframework.security.web.server.csrf.CsrfException.class,
				(r) -> new org.springframework.security.web.server.csrf.CsrfException("message"));
		generatorByClassName.put(InvalidCsrfTokenException.class,
				(r) -> new InvalidCsrfTokenException(new DefaultCsrfToken("header", "parameter", "token"), "token"));
		generatorByClassName.put(MissingCsrfTokenException.class, (r) -> new MissingCsrfTokenException("token"));
		generatorByClassName.put(DefaultCsrfToken.class, (r) -> new DefaultCsrfToken("header", "parameter", "token"));
		generatorByClassName.put(org.springframework.security.web.server.csrf.DefaultCsrfToken.class,
				(r) -> new org.springframework.security.web.server.csrf.DefaultCsrfToken("header", "parameter",
						"token"));
		generatorByClassName.put(RequestRejectedException.class, (r) -> new RequestRejectedException("message"));
		generatorByClassName.put(ServerExchangeRejectedException.class,
				(r) -> new ServerExchangeRejectedException("message"));
		generatorByClassName.put(SessionFixationProtectionEvent.class,
				(r) -> new SessionFixationProtectionEvent(authentication, "old", "new"));
		generatorByClassName.put(AuthenticationSwitchUserEvent.class,
				(r) -> new AuthenticationSwitchUserEvent(authentication, user));
		generatorByClassName.put(HttpSessionCreatedEvent.class,
				(r) -> new HttpSessionCreatedEvent(new MockHttpSession()));
	}

	@ParameterizedTest
	@MethodSource("getClassesToSerialize")
	@Disabled("This method should only be used to serialize the classes once")
	void serializeCurrentVersionClasses(Class<?> clazz) throws Exception {
		Files.createDirectories(currentVersionFolder);
		Path filePath = Paths.get(currentVersionFolder.toAbsolutePath() + "/" + clazz.getName() + ".serialized");
		File file = filePath.toFile();
		if (file.exists()) {
			return;
		}
		Files.createFile(filePath);
		Object instance = instancioWithDefaults(clazz).create();
		assertThat(instance).isInstanceOf(clazz);
		try (FileOutputStream fileOutputStream = new FileOutputStream(file);
				ObjectOutputStream objectOutputStream = new ObjectOutputStream(fileOutputStream)) {
			objectOutputStream.writeObject(instance);
			objectOutputStream.flush();
		}
		catch (NotSerializableException ex) {
			Files.delete(filePath);
			fail("Could not serialize " + clazz.getName(), ex);
		}
	}

	@ParameterizedTest
	@MethodSource("getFilesToDeserialize")
	void shouldBeAbleToDeserializeClassFromPreviousVersion(Path filePath) {
		try (FileInputStream fileInputStream = new FileInputStream(filePath.toFile());
				ObjectInputStream objectInputStream = new ObjectInputStream(fileInputStream)) {
			Object obj = objectInputStream.readObject();
			Class<?> clazz = Class.forName(filePath.getFileName().toString().replace(".serialized", ""));
			assertThat(obj).isInstanceOf(clazz);
		}
		catch (IOException | ClassNotFoundException ex) {
			fail("Could not deserialize " + filePath, ex);
		}
	}

	static Stream<Path> getFilesToDeserialize() throws IOException {
		assertThat(previousVersionFolder.toFile().exists())
			.as("Make sure that the " + previousVersionFolder + " exists and is not empty")
			.isTrue();
		try (Stream<Path> files = Files.list(previousVersionFolder)) {
			if (files.findFirst().isEmpty()) {
				fail("Please make sure to run SpringSecurityCoreVersionSerializableTests#serializeCurrentVersionClasses for the "
						+ getPreviousVersion() + " version");
			}
		}
		return Files.list(previousVersionFolder);
	}

	@Test
	void listClassesMissingSerialVersion() throws Exception {
		ClassPathScanningCandidateComponentProvider provider = new ClassPathScanningCandidateComponentProvider(false);
		provider.addIncludeFilter(new AssignableTypeFilter(Serializable.class));
		List<Class<?>> classes = new ArrayList<>();

		Set<BeanDefinition> components = provider.findCandidateComponents("org/springframework/security");
		for (BeanDefinition component : components) {
			Class<?> clazz = Class.forName(component.getBeanClassName());
			boolean isAbstract = Modifier.isAbstract(clazz.getModifiers());
			if (isAbstract) {
				continue;
			}
			if (clazz.isEnum()) {
				continue;
			}
			if (clazz.getName().contains("Tests")) {
				continue;
			}
			boolean hasSerialVersion = Stream.of(clazz.getDeclaredFields())
				.map(Field::getName)
				.anyMatch((n) -> n.equals("serialVersionUID"));
			if (!hasSerialVersion) {
				classes.add(clazz);
			}
		}
		if (!classes.isEmpty()) {
			System.out
				.println("Found " + classes.size() + " Serializable classes that don't declare a seriallVersionUID");
			System.out.println(classes.stream().map(Class::getName).collect(Collectors.joining("\r\n")));
		}
	}

	static Stream<Class<?>> getClassesToSerialize() throws Exception {
		ClassPathScanningCandidateComponentProvider provider = new ClassPathScanningCandidateComponentProvider(false);
		provider.addIncludeFilter(new AssignableTypeFilter(Serializable.class));
		List<Class<?>> classes = new ArrayList<>();

		Set<BeanDefinition> components = provider.findCandidateComponents("org/springframework/security");
		for (BeanDefinition component : components) {
			Class<?> clazz = Class.forName(component.getBeanClassName());
			boolean isAbstract = Modifier.isAbstract(clazz.getModifiers());
			if (isAbstract) {
				continue;
			}
			boolean matchesExpectedSerialVersion = ObjectStreamClass.lookup(clazz)
				.getSerialVersionUID() == securitySerialVersionUid;
			boolean isUnderTest = generatorByClassName.containsKey(clazz);
			if (matchesExpectedSerialVersion || isUnderTest) {
				classes.add(clazz);
			}
		}
		return classes.stream();
	}

	private static InstancioApi<?> instancioWithDefaults(Class<?> clazz) {
		InstancioApi<?> instancio = Instancio.of(clazz);
		if (generatorByClassName.containsKey(clazz)) {
			instancio.supply(Select.all(clazz), generatorByClassName.get(clazz));
		}
		return instancio;
	}

	private static <T extends AbstractAuthenticationToken> T applyDetails(T authentication) {
		WebAuthenticationDetails details = new WebAuthenticationDetails("remote", "sessionId");
		authentication.setDetails(details);
		return authentication;
	}

	private static String getCurrentVersion() {
		String version = System.getProperty("springSecurityVersion");
		String[] parts = version.split("\\.");
		parts[2] = "x";
		return String.join(".", parts);
	}

	private static String getPreviousVersion() {
		String version = System.getProperty("springSecurityVersion");
		String[] parts = version.split("\\.");
		parts[1] = String.valueOf(Integer.parseInt(parts[1]) - 1);
		parts[2] = "x";
		return String.join(".", parts);
	}

}
