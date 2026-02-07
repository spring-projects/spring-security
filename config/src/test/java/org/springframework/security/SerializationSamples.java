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

package org.springframework.security;

import java.io.IOException;
import java.io.Serializable;
import java.lang.reflect.Field;
import java.security.Principal;
import java.time.Instant;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.function.Supplier;

import jakarta.servlet.http.Cookie;
import org.apereo.cas.client.validation.AssertionImpl;
import org.instancio.Instancio;
import org.instancio.InstancioApi;
import org.instancio.InstancioOfClassApi;
import org.instancio.Select;
import org.instancio.generator.Generator;

import org.springframework.core.ResolvableType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.AuthorizationServiceException;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.access.hierarchicalroles.CycleInRoleHierarchyException;
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
import org.springframework.security.authentication.ott.DefaultOneTimeToken;
import org.springframework.security.authentication.ott.InvalidOneTimeTokenException;
import org.springframework.security.authentication.ott.OneTimeTokenAuthentication;
import org.springframework.security.authentication.ott.OneTimeTokenAuthenticationToken;
import org.springframework.security.authentication.password.CompromisedPasswordException;
import org.springframework.security.authorization.AuthorityAuthorizationDecision;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationDeniedException;
import org.springframework.security.authorization.event.AuthorizationEvent;
import org.springframework.security.authorization.event.AuthorizationGrantedEvent;
import org.springframework.security.cas.authentication.CasAssertionAuthenticationToken;
import org.springframework.security.cas.authentication.CasAuthenticationToken;
import org.springframework.security.cas.authentication.CasServiceTicketAuthenticationToken;
import org.springframework.security.config.annotation.AlreadyBuiltException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.core.context.TransientSecurityContext;
import org.springframework.security.core.session.AbstractSessionEvent;
import org.springframework.security.core.session.ReactiveSessionInformation;
import org.springframework.security.core.session.SessionInformation;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.ldap.ppolicy.PasswordPolicyControl;
import org.springframework.security.ldap.ppolicy.PasswordPolicyErrorStatus;
import org.springframework.security.ldap.ppolicy.PasswordPolicyException;
import org.springframework.security.ldap.ppolicy.PasswordPolicyResponseControl;
import org.springframework.security.ldap.userdetails.LdapAuthority;
import org.springframework.security.oauth2.client.ClientAuthorizationException;
import org.springframework.security.oauth2.client.ClientAuthorizationRequiredException;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthorizationCodeAuthenticationToken;
import org.springframework.security.oauth2.client.authentication.OAuth2LoginAuthenticationToken;
import org.springframework.security.oauth2.client.authentication.TestOAuth2AuthenticationTokens;
import org.springframework.security.oauth2.client.authentication.TestOAuth2AuthorizationCodeAuthenticationTokens;
import org.springframework.security.oauth2.client.event.OAuth2AuthorizedClientRefreshedEvent;
import org.springframework.security.oauth2.client.oidc.authentication.event.OidcUserRefreshedEvent;
import org.springframework.security.oauth2.client.oidc.authentication.logout.OidcLogoutToken;
import org.springframework.security.oauth2.client.oidc.authentication.logout.TestOidcLogoutTokens;
import org.springframework.security.oauth2.client.oidc.session.OidcSessionInformation;
import org.springframework.security.oauth2.client.oidc.session.TestOidcSessionInformations;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.TestClientRegistrations;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
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
import org.springframework.security.oauth2.core.endpoint.TestOAuth2AccessTokenResponses;
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
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationServerMetadata;
import org.springframework.security.oauth2.server.authorization.OAuth2ClientRegistration;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenIntrospection;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.TestOAuth2Authorizations;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationConsentAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationGrantAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientRegistrationAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2DeviceAuthorizationConsentAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2DeviceAuthorizationRequestAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2DeviceVerificationAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2PushedAuthorizationRequestAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenIntrospectionAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenRevocationAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.TestRegisteredClients;
import org.springframework.security.oauth2.server.authorization.oidc.OidcClientRegistration;
import org.springframework.security.oauth2.server.authorization.oidc.OidcProviderConfiguration;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcClientRegistrationAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcLogoutAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcUserInfoAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.resource.BearerTokenError;
import org.springframework.security.oauth2.server.resource.BearerTokenErrors;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.security.oauth2.server.resource.OAuth2ProtectedResourceMetadata;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthentication;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.DPoPAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.introspection.BadOpaqueTokenException;
import org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionAuthenticatedPrincipal;
import org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionException;
import org.springframework.security.saml2.Saml2Exception;
import org.springframework.security.saml2.core.Saml2Error;
import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.security.saml2.credentials.TestSaml2X509Credentials;
import org.springframework.security.saml2.provider.service.authentication.DefaultSaml2AuthenticatedPrincipal;
import org.springframework.security.saml2.provider.service.authentication.Saml2AssertionAuthentication;
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationException;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationToken;
import org.springframework.security.saml2.provider.service.authentication.Saml2PostAuthenticationRequest;
import org.springframework.security.saml2.provider.service.authentication.Saml2RedirectAuthenticationRequest;
import org.springframework.security.saml2.provider.service.authentication.Saml2ResponseAssertion;
import org.springframework.security.saml2.provider.service.authentication.Saml2ResponseAssertionAccessor;
import org.springframework.security.saml2.provider.service.authentication.TestOpenSamlObjects;
import org.springframework.security.saml2.provider.service.authentication.TestSaml2AuthenticationTokens;
import org.springframework.security.saml2.provider.service.authentication.TestSaml2Authentications;
import org.springframework.security.saml2.provider.service.authentication.TestSaml2LogoutRequests;
import org.springframework.security.saml2.provider.service.authentication.TestSaml2PostAuthenticationRequests;
import org.springframework.security.saml2.provider.service.authentication.TestSaml2RedirectAuthenticationRequests;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutRequest;
import org.springframework.security.saml2.provider.service.registration.OpenSamlAssertingPartyDetails;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.TestRelyingPartyRegistrations;
import org.springframework.security.web.authentication.AuthenticationFilter;
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
import org.springframework.security.web.savedrequest.DefaultSavedRequest;
import org.springframework.security.web.savedrequest.SimpleSavedRequest;
import org.springframework.security.web.server.firewall.ServerExchangeRejectedException;
import org.springframework.security.web.session.HttpSessionCreatedEvent;
import org.springframework.security.web.session.HttpSessionIdChangedEvent;
import org.springframework.security.web.webauthn.api.AuthenticationExtensionsClientInputs;
import org.springframework.security.web.webauthn.api.AuthenticationExtensionsClientOutputs;
import org.springframework.security.web.webauthn.api.AuthenticatorAssertionResponse;
import org.springframework.security.web.webauthn.api.AuthenticatorAttachment;
import org.springframework.security.web.webauthn.api.AuthenticatorTransport;
import org.springframework.security.web.webauthn.api.Bytes;
import org.springframework.security.web.webauthn.api.CredProtectAuthenticationExtensionsClientInput;
import org.springframework.security.web.webauthn.api.CredentialPropertiesOutput;
import org.springframework.security.web.webauthn.api.ImmutableAuthenticationExtensionsClientInput;
import org.springframework.security.web.webauthn.api.ImmutableAuthenticationExtensionsClientInputs;
import org.springframework.security.web.webauthn.api.ImmutableAuthenticationExtensionsClientOutputs;
import org.springframework.security.web.webauthn.api.ImmutablePublicKeyCredentialUserEntity;
import org.springframework.security.web.webauthn.api.PublicKeyCredential;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialDescriptor;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialRequestOptions;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialType;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialUserEntity;
import org.springframework.security.web.webauthn.api.TestAuthenticationAssertionResponses;
import org.springframework.security.web.webauthn.api.TestBytes;
import org.springframework.security.web.webauthn.api.TestPublicKeyCredentialRequestOptions;
import org.springframework.security.web.webauthn.api.TestPublicKeyCredentialUserEntities;
import org.springframework.security.web.webauthn.api.TestPublicKeyCredentials;
import org.springframework.security.web.webauthn.api.UserVerificationRequirement;
import org.springframework.security.web.webauthn.authentication.WebAuthnAuthentication;
import org.springframework.security.web.webauthn.authentication.WebAuthnAuthenticationRequestToken;
import org.springframework.security.web.webauthn.management.RelyingPartyAuthenticationRequest;
import org.springframework.util.ReflectionUtils;

final class SerializationSamples {

	static final Map<Class<?>, Generator<?>> generatorByClassName = new HashMap<>();

	static final Map<Class<?>, Supplier<InstancioApi<?>>> instancioByClassName = new HashMap<>();

	static {
		UserDetails user = TestAuthentication.user();
		Authentication authentication = TestAuthentication.authenticated(user);
		SecurityContext securityContext = new SecurityContextImpl(authentication);

		instancioByClassName.put(OneTimeTokenAuthenticationToken.class, () -> {
			InstancioOfClassApi<?> instancio = Instancio.of(OneTimeTokenAuthenticationToken.class);
			instancio.supply(Select.all(OneTimeTokenAuthenticationToken.class),
					(r) -> applyDetails(new OneTimeTokenAuthenticationToken("token")));
			return instancio;
		});

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
				(r) -> new OAuth2DeviceCode("token", Instant.now(), Instant.now().plusSeconds(1)));
		generatorByClassName.put(OAuth2RefreshToken.class,
				(r) -> new OAuth2RefreshToken("refreshToken", Instant.now(), Instant.now().plusSeconds(1)));
		generatorByClassName.put(OAuth2UserCode.class,
				(r) -> new OAuth2UserCode("token", Instant.now(), Instant.now().plusSeconds(1)));
		generatorByClassName.put(ClientRegistration.ClientSettings.class,
				(r) -> ClientRegistration.ClientSettings.builder().build());
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
		generatorByClassName
			.put(OAuth2AuthorizedClientRefreshedEvent.class, (r) -> new OAuth2AuthorizedClientRefreshedEvent(
					TestOAuth2AccessTokenResponses.accessTokenResponse().build(),
					new OAuth2AuthorizedClient(clientRegistration, "principal", TestOAuth2AccessTokens.noScopes())));
		generatorByClassName.put(OidcUserRefreshedEvent.class,
				(r) -> new OidcUserRefreshedEvent(TestOAuth2AccessTokenResponses.accessTokenResponse().build(),
						TestOidcUsers.create(), TestOidcUsers.create(), authentication));

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
		generatorByClassName.put(DPoPAuthenticationToken.class,
				(r) -> applyDetails(new DPoPAuthenticationToken("token", "proof", "method", "uri")));
		generatorByClassName.put(OAuth2ProtectedResourceMetadata.class,
				(r) -> OAuth2ProtectedResourceMetadata.builder()
					.resource("https://localhost/resource")
					.authorizationServer("https://localhost/authorizationServer")
					.scope("scope")
					.bearerMethod("bearerMethod")
					.resourceName("resourceName")
					.tlsClientCertificateBoundAccessTokens(true)
					.build());

		// oauth2-authorization-server
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient).build();
		OAuth2AuthorizationRequest authorizationRequest = authorization
			.getAttribute(OAuth2AuthorizationRequest.class.getName());
		Authentication principal = authorization.getAttribute(Principal.class.getName());
		generatorByClassName.put(RegisteredClient.class, (r) -> registeredClient);
		generatorByClassName.put(OAuth2Authorization.class, (r) -> authorization);
		generatorByClassName.put(OAuth2Authorization.Token.class, (r) -> authorization.getAccessToken());
		generatorByClassName.put(OAuth2AuthorizationConsent.class,
				(r) -> OAuth2AuthorizationConsent.withId("registeredClientId", "principalName")
					.scope("scope1")
					.scope("scope2")
					.build());
		generatorByClassName.put(OAuth2AuthorizationCodeRequestAuthenticationToken.class, (r) -> {
			OAuth2AuthorizationCodeRequestAuthenticationToken authenticationToken = new OAuth2AuthorizationCodeRequestAuthenticationToken(
					"authorizationUri", "clientId", principal, "redirectUri", "state", authorizationRequest.getScopes(),
					authorizationRequest.getAdditionalParameters());
			authenticationToken.setDetails(details);
			return authenticationToken;
		});
		generatorByClassName.put(OAuth2PushedAuthorizationRequestAuthenticationToken.class, (r) -> {
			OAuth2PushedAuthorizationRequestAuthenticationToken authenticationToken = new OAuth2PushedAuthorizationRequestAuthenticationToken(
					"authorizationUri", "clientId", principal, "redirectUri", "state", authorizationRequest.getScopes(),
					authorizationRequest.getAdditionalParameters());
			authenticationToken.setDetails(details);
			return authenticationToken;
		});
		generatorByClassName.put(OAuth2AuthorizationGrantAuthenticationToken.class, (r) -> {
			org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeAuthenticationToken authenticationToken = new org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeAuthenticationToken(
					"code", principal, "redirectUri", new HashMap<>());
			authenticationToken.setDetails(details);
			return authenticationToken;
		});
		generatorByClassName.put(OAuth2AuthorizationConsentAuthenticationToken.class, (r) -> {
			OAuth2AuthorizationConsentAuthenticationToken authenticationToken = new OAuth2AuthorizationConsentAuthenticationToken(
					"authorizationUri", "clientId", principal, "state", authorizationRequest.getScopes(),
					authorizationRequest.getAdditionalParameters());
			authenticationToken.setDetails(details);
			return authenticationToken;
		});
		generatorByClassName.put(OAuth2DeviceAuthorizationRequestAuthenticationToken.class, (r) -> {
			OAuth2DeviceAuthorizationRequestAuthenticationToken authenticationToken = new OAuth2DeviceAuthorizationRequestAuthenticationToken(
					principal, "authorizationUri", authorizationRequest.getScopes(),
					authorizationRequest.getAdditionalParameters());
			authenticationToken.setDetails(details);
			return authenticationToken;
		});
		generatorByClassName.put(OAuth2DeviceAuthorizationConsentAuthenticationToken.class, (r) -> {
			OAuth2DeviceAuthorizationConsentAuthenticationToken authenticationToken = new OAuth2DeviceAuthorizationConsentAuthenticationToken(
					"authorizationUri", "clientId", principal, "userCode", "state", authorizationRequest.getScopes(),
					authorizationRequest.getAdditionalParameters());
			authenticationToken.setDetails(details);
			return authenticationToken;
		});
		generatorByClassName.put(OAuth2DeviceVerificationAuthenticationToken.class, (r) -> {
			OAuth2DeviceVerificationAuthenticationToken authenticationToken = new OAuth2DeviceVerificationAuthenticationToken(
					principal, "userCode", new HashMap<>());
			authenticationToken.setDetails(details);
			return authenticationToken;
		});
		generatorByClassName.put(OAuth2TokenIntrospectionAuthenticationToken.class, (r) -> {
			OAuth2TokenIntrospectionAuthenticationToken authenticationToken = new OAuth2TokenIntrospectionAuthenticationToken(
					"token", principal, "tokenTypeHint", new HashMap<>());
			authenticationToken.setDetails(details);
			return authenticationToken;
		});
		generatorByClassName.put(OAuth2TokenRevocationAuthenticationToken.class, (r) -> {
			OAuth2TokenRevocationAuthenticationToken authenticationToken = new OAuth2TokenRevocationAuthenticationToken(
					"token", principal, "tokenTypeHint");
			authenticationToken.setDetails(details);
			return authenticationToken;
		});
		OAuth2ClientRegistration oauth2ClientRegistration = OAuth2ClientRegistration.builder()
			.grantType(AuthorizationGrantType.AUTHORIZATION_CODE.getValue())
			.scope("scope1")
			.redirectUri("https://localhost/oauth2/callback")
			.build();
		generatorByClassName.put(OAuth2ClientRegistration.class, (r) -> oauth2ClientRegistration);
		generatorByClassName.put(OAuth2ClientRegistrationAuthenticationToken.class, (r) -> {
			OAuth2ClientRegistrationAuthenticationToken authenticationToken = new OAuth2ClientRegistrationAuthenticationToken(
					principal, oauth2ClientRegistration);
			authenticationToken.setDetails(details);
			return authenticationToken;
		});
		OidcClientRegistration oidcClientRegistration = OidcClientRegistration.builder()
			.grantType(AuthorizationGrantType.AUTHORIZATION_CODE.getValue())
			.scope("scope1")
			.redirectUri("https://localhost/oauth2/callback")
			.build();
		generatorByClassName.put(OidcClientRegistration.class, (r) -> oidcClientRegistration);
		generatorByClassName.put(OidcClientRegistrationAuthenticationToken.class, (r) -> {
			OidcClientRegistrationAuthenticationToken authenticationToken = new OidcClientRegistrationAuthenticationToken(
					principal, oidcClientRegistration);
			authenticationToken.setDetails(details);
			return authenticationToken;
		});
		generatorByClassName.put(OidcUserInfoAuthenticationToken.class, (r) -> {
			OidcUserInfo userInfo = OidcUserInfo.builder().subject("subject").name("name").build();
			OidcUserInfoAuthenticationToken authenticationToken = new OidcUserInfoAuthenticationToken(principal,
					userInfo);
			authenticationToken.setDetails(details);
			return authenticationToken;
		});
		generatorByClassName.put(OidcLogoutAuthenticationToken.class, (r) -> {
			OidcIdToken idToken = OidcIdToken.withTokenValue("tokenValue")
				.issuedAt(Instant.now())
				.expiresAt(Instant.now().plusSeconds(60))
				.build();
			OidcLogoutAuthenticationToken authenticationToken = new OidcLogoutAuthenticationToken(idToken, principal,
					"sessionId", "clientId", "postLogoutRedirectUri", "state");
			authenticationToken.setDetails(details);
			return authenticationToken;
		});
		generatorByClassName.put(OAuth2ClientAuthenticationToken.class, (r) -> {
			OAuth2ClientAuthenticationToken authenticationToken = new OAuth2ClientAuthenticationToken(registeredClient,
					ClientAuthenticationMethod.CLIENT_SECRET_BASIC, "credentials");
			authenticationToken.setDetails(details);
			return authenticationToken;
		});
		generatorByClassName.put(OAuth2TokenIntrospection.class,
				(r) -> OAuth2TokenIntrospection.builder().active(true).clientId("clientId").build());
		generatorByClassName.put(OAuth2AccessTokenAuthenticationToken.class, (r) -> {
			OAuth2AccessTokenAuthenticationToken authenticationToken = new OAuth2AccessTokenAuthenticationToken(
					registeredClient, principal, authorization.getAccessToken().getToken());
			authenticationToken.setDetails(details);
			return authenticationToken;
		});
		generatorByClassName.put(OAuth2AuthorizationServerMetadata.class,
				(r) -> OAuth2AuthorizationServerMetadata.builder()
					.issuer("https://localhost")
					.authorizationEndpoint("https://localhost/oauth2/authorize")
					.tokenEndpoint("https://localhost/oauth2/token")
					.responseType("code")
					.build());
		generatorByClassName.put(OidcProviderConfiguration.class,
				(r) -> OidcProviderConfiguration.builder()
					.issuer("https://localhost")
					.authorizationEndpoint("https://localhost/oauth2/authorize")
					.tokenEndpoint("https://localhost/oauth2/token")
					.jwkSetUrl("https://localhost/oauth2/jwks")
					.responseType("code")
					.subjectType("subjectType")
					.idTokenSigningAlgorithm("RS256")
					.build());
		generatorByClassName.put(OAuth2TokenType.class, (r) -> OAuth2TokenType.ACCESS_TOKEN);
		generatorByClassName.put(OAuth2TokenFormat.class, (r) -> OAuth2TokenFormat.SELF_CONTAINED);
		generatorByClassName.put(AuthorizationServerSettings.class,
				(r) -> AuthorizationServerSettings.builder().build());
		generatorByClassName.put(ClientSettings.class, (r) -> ClientSettings.builder().build());
		generatorByClassName.put(TokenSettings.class, (r) -> TokenSettings.builder().build());

		// config
		generatorByClassName.put(AlreadyBuiltException.class, (r) -> new AlreadyBuiltException("message"));

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
		generatorByClassName.put(FactorGrantedAuthority.class,
				(r) -> FactorGrantedAuthority.withAuthority("profile:read").issuedAt(Instant.now()).build());
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

		generatorByClassName.put(OneTimeTokenAuthentication.class,
				(r) -> applyDetails(new OneTimeTokenAuthentication("username", authentication.getAuthorities())));
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
				(r) -> new InteractiveAuthenticationSuccessEvent(authentication, AuthenticationFilter.class));
		generatorByClassName.put(LogoutSuccessEvent.class, (r) -> new LogoutSuccessEvent(authentication));
		generatorByClassName.put(JaasAuthenticationFailedEvent.class,
				(r) -> new JaasAuthenticationFailedEvent(authentication, new RuntimeException("message")));
		generatorByClassName.put(JaasAuthenticationSuccessEvent.class,
				(r) -> new JaasAuthenticationSuccessEvent(authentication));
		generatorByClassName.put(AbstractSessionEvent.class, (r) -> new AbstractSessionEvent(securityContext));
		generatorByClassName.put(SecurityConfig.class, (r) -> new SecurityConfig("value"));
		generatorByClassName.put(TransientSecurityContext.class, (r) -> new TransientSecurityContext(authentication));
		generatorByClassName.put(AuthorizationDeniedException.class,
				(r) -> new AuthorizationDeniedException("message", new AuthorizationDecision(false)));
		generatorByClassName.put(AuthorizationDecision.class, (r) -> new AuthorizationDecision(true));
		generatorByClassName.put(AuthorityAuthorizationDecision.class,
				(r) -> new AuthorityAuthorizationDecision(true, AuthorityUtils.createAuthorityList("ROLE_USER")));
		generatorByClassName.put(CycleInRoleHierarchyException.class, (r) -> new CycleInRoleHierarchyException());
		generatorByClassName.put(AuthorizationEvent.class,
				(r) -> new AuthorizationEvent(new SerializableSupplier<>(authentication), "source",
						new AuthorizationDecision(true)));
		generatorByClassName.put(AuthorizationGrantedEvent.class,
				(r) -> new AuthorizationGrantedEvent<>(new SerializableSupplier<>(authentication), "source",
						new AuthorizationDecision(true)));
		instancioByClassName.put(AuthorizationGrantedEvent.class, () -> {
			InstancioOfClassApi<?> instancio = Instancio.of(AuthorizationGrantedEvent.class);
			instancio.withTypeParameters(String.class);
			instancio.supply(Select.all(AuthorizationGrantedEvent.class),
					generatorByClassName.get(AuthorizationGrantedEvent.class));
			return instancio;
		});

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
		generatorByClassName.put(PasswordPolicyControl.class, (r) -> new PasswordPolicyControl(true));
		generatorByClassName.put(PasswordPolicyResponseControl.class, (r) -> {
			byte[] encodedResponse = { 0x30, 0x05, (byte) 0xA0, 0x03, (byte) 0xA0, 0x1, 0x21 };
			return new PasswordPolicyResponseControl(encodedResponse);
		});

		// saml2-service-provider
		generatorByClassName.put(Saml2AuthenticationException.class,
				(r) -> new Saml2AuthenticationException(new Saml2Error("code", "descirption"), "message",
						new IOException("fail")));
		generatorByClassName.put(Saml2Exception.class, (r) -> new Saml2Exception("message", new IOException("fail")));
		generatorByClassName.put(DefaultSaml2AuthenticatedPrincipal.class,
				(r) -> TestSaml2Authentications.authentication().getPrincipal());
		Saml2Authentication saml2 = TestSaml2Authentications.authentication();
		generatorByClassName.put(Saml2Authentication.class, (r) -> applyDetails(saml2));
		Saml2ResponseAssertionAccessor assertion = Saml2ResponseAssertion.withResponseValue("response")
			.nameId("name")
			.sessionIndexes(List.of("id"))
			.attributes(Map.of("key", List.of("value")))
			.build();
		generatorByClassName.put(Saml2ResponseAssertion.class, (r) -> assertion);
		generatorByClassName.put(Saml2AssertionAuthentication.class, (r) -> applyDetails(
				new Saml2AssertionAuthentication(assertion, authentication.getAuthorities(), "id")));
		generatorByClassName.put(Saml2PostAuthenticationRequest.class,
				(r) -> TestSaml2PostAuthenticationRequests.create());
		generatorByClassName.put(Saml2RedirectAuthenticationRequest.class,
				(r) -> TestSaml2RedirectAuthenticationRequests.create());
		generatorByClassName.put(Saml2X509Credential.class,
				(r) -> TestSaml2X509Credentials.relyingPartyVerifyingCredential());
		generatorByClassName.put(RelyingPartyRegistration.AssertingPartyDetails.class,
				(r) -> TestRelyingPartyRegistrations.full().build().getAssertingPartyMetadata());
		generatorByClassName.put(RelyingPartyRegistration.class, (r) -> TestRelyingPartyRegistrations.full().build());
		generatorByClassName.put(Saml2AuthenticationToken.class, (r) -> {
			Saml2AuthenticationToken token = TestSaml2AuthenticationTokens.tokenRequested();
			token.setDetails(details);
			return token;
		});
		generatorByClassName.put(Saml2LogoutRequest.class, (r) -> TestSaml2LogoutRequests.create());
		generatorByClassName.put(OpenSamlAssertingPartyDetails.class,
				(r) -> OpenSamlAssertingPartyDetails
					.withEntityDescriptor(
							TestOpenSamlObjects.entityDescriptor(TestRelyingPartyRegistrations.full().build()))
					.build());

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
		generatorByClassName.put(SimpleSavedRequest.class, (r) -> {
			MockHttpServletRequest request = new MockHttpServletRequest("GET", "/uri");
			request.setQueryString("query=string");
			request.setScheme("https");
			request.setServerName("localhost");
			request.setServerPort(80);
			request.setRequestURI("/uri");
			request.setCookies(new Cookie("name", "value"));
			request.addHeader("header", "value");
			request.addParameter("parameter", "value");
			request.setPathInfo("/path");
			request.addPreferredLocale(Locale.ENGLISH);
			return new SimpleSavedRequest(new DefaultSavedRequest(request, "continue"));
		});

		generatorByClassName.put(HttpSessionIdChangedEvent.class,
				(r) -> new HttpSessionIdChangedEvent(new MockHttpSession(), "1"));

		// webauthn
		CredProtectAuthenticationExtensionsClientInput.CredProtect credProtect = new CredProtectAuthenticationExtensionsClientInput.CredProtect(
				CredProtectAuthenticationExtensionsClientInput.CredProtect.ProtectionPolicy.USER_VERIFICATION_OPTIONAL,
				true);
		Bytes id = TestBytes.get();
		AuthenticationExtensionsClientInputs inputs = new ImmutableAuthenticationExtensionsClientInputs(
				ImmutableAuthenticationExtensionsClientInput.credProps);
		// @formatter:off
		PublicKeyCredentialDescriptor descriptor = PublicKeyCredentialDescriptor.builder()
				.id(id)
				.type(PublicKeyCredentialType.PUBLIC_KEY)
				.transports(Set.of(AuthenticatorTransport.USB))
				.build();
		// @formatter:on
		generatorByClassName.put(AuthenticatorTransport.class, (a) -> AuthenticatorTransport.USB);
		generatorByClassName.put(PublicKeyCredentialType.class, (k) -> PublicKeyCredentialType.PUBLIC_KEY);
		generatorByClassName.put(UserVerificationRequirement.class, (r) -> UserVerificationRequirement.REQUIRED);
		generatorByClassName.put(CredProtectAuthenticationExtensionsClientInput.CredProtect.class, (c) -> credProtect);
		generatorByClassName.put(CredProtectAuthenticationExtensionsClientInput.class,
				(c) -> new CredProtectAuthenticationExtensionsClientInput(credProtect));
		generatorByClassName.put(ImmutableAuthenticationExtensionsClientInputs.class, (i) -> inputs);
		Field credPropsField = ReflectionUtils.findField(ImmutableAuthenticationExtensionsClientInput.class,
				"credProps");
		generatorByClassName.put(credPropsField.getType(),
				(i) -> ImmutableAuthenticationExtensionsClientInput.credProps);
		generatorByClassName.put(Bytes.class, (b) -> id);
		generatorByClassName.put(PublicKeyCredentialDescriptor.class, (d) -> descriptor);
		// @formatter:off
		generatorByClassName.put(PublicKeyCredentialRequestOptions.class, (o) -> TestPublicKeyCredentialRequestOptions.create()
				.extensions(inputs)
				.allowCredentials(List.of(descriptor))
				.build()
		);

		CredentialPropertiesOutput credentialOutput = new CredentialPropertiesOutput(false);
		AuthenticationExtensionsClientOutputs outputs = new ImmutableAuthenticationExtensionsClientOutputs(credentialOutput);
		AuthenticatorAssertionResponse response = TestAuthenticationAssertionResponses.createAuthenticatorAssertionResponse()
				.build();
		PublicKeyCredential<AuthenticatorAssertionResponse> credential = TestPublicKeyCredentials.createPublicKeyCredential(
						response, outputs)
				.build();
		RelyingPartyAuthenticationRequest authRequest = new RelyingPartyAuthenticationRequest(
				TestPublicKeyCredentialRequestOptions.create().build(),
				credential
		);
		WebAuthnAuthenticationRequestToken requestToken = new WebAuthnAuthenticationRequestToken(authRequest);
		requestToken.setDetails(details);
		generatorByClassName.put(CredentialPropertiesOutput.class, (o) -> credentialOutput);
		generatorByClassName.put(ImmutableAuthenticationExtensionsClientOutputs.class, (o) -> outputs);
		generatorByClassName.put(AuthenticatorAssertionResponse.class, (r) -> response);
		generatorByClassName.put(RelyingPartyAuthenticationRequest.class, (r) -> authRequest);
		generatorByClassName.put(PublicKeyCredential.class, (r) -> credential);
		generatorByClassName.put(WebAuthnAuthenticationRequestToken.class, (r) -> requestToken);
		generatorByClassName.put(AuthenticatorAttachment.class, (r) -> AuthenticatorAttachment.PLATFORM);
		// @formatter:on
		generatorByClassName.put(ImmutablePublicKeyCredentialUserEntity.class,
				(r) -> TestPublicKeyCredentialUserEntities.userEntity().id(TestBytes.get()).build());
		generatorByClassName.put(WebAuthnAuthentication.class, (r) -> {
			PublicKeyCredentialUserEntity userEntity = TestPublicKeyCredentialUserEntities.userEntity()
				.id(TestBytes.get())
				.build();
			List<GrantedAuthority> authorities = AuthorityUtils.createAuthorityList("ROLE_USER");
			WebAuthnAuthentication webAuthnAuthentication = new WebAuthnAuthentication(userEntity, authorities);
			webAuthnAuthentication.setDetails(details);
			return webAuthnAuthentication;
		});
		// @formatter:on

		generatorByClassName.put(CredentialPropertiesOutput.ExtensionOutput.class,
				(r) -> new CredentialPropertiesOutput(true).getOutput());

		// One-Time Token
		DefaultOneTimeToken oneTimeToken = new DefaultOneTimeToken(UUID.randomUUID().toString(), "user",
				Instant.now().plusSeconds(300));
		generatorByClassName.put(DefaultOneTimeToken.class, (t) -> oneTimeToken);
	}

	private SerializationSamples() {

	}

	static InstancioApi<?> instancioWithDefaults(Class<?> clazz) {
		if (instancioByClassName.containsKey(clazz)) {
			return instancioByClassName.get(clazz).get();
		}
		InstancioOfClassApi<?> instancio = Instancio.of(clazz);
		ResolvableType[] generics = ResolvableType.forClass(clazz).getGenerics();
		for (ResolvableType type : generics) {
			instancio.withTypeParameters(type.resolve());
		}
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

	@SuppressWarnings("serial")
	private static final class SerializableSupplier<T> implements Supplier<T>, Serializable {

		private final T value;

		SerializableSupplier(T value) {
			this.value = value;
		}

		@Override
		public T get() {
			return this.value;
		}

	}

}
