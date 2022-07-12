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

package org.springframework.security.saml2.jackson2;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.saml2.core.Saml2Error;
import org.springframework.security.saml2.provider.service.authentication.DefaultSaml2AuthenticatedPrincipal;
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationException;
import org.springframework.security.saml2.provider.service.authentication.Saml2PostAuthenticationRequest;
import org.springframework.security.saml2.provider.service.authentication.Saml2RedirectAuthenticationRequest;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutRequest;
import org.springframework.security.saml2.provider.service.registration.Saml2MessageBinding;
import org.springframework.security.saml2.provider.service.registration.TestRelyingPartyRegistrations;

final class TestSaml2JsonPayloads {

	private TestSaml2JsonPayloads() {
	}

	static final Map<String, List<Object>> ATTRIBUTES;

	static {
		Map<String, List<Object>> tmpAttributes = new HashMap<>();
		tmpAttributes.put("name", Collections.singletonList("attr_name"));
		tmpAttributes.put("email", Collections.singletonList("attr_email"));
		tmpAttributes.put("listOf", Collections.unmodifiableList(Arrays.asList("Element1", "Element2", 4, true)));
		ATTRIBUTES = Collections.unmodifiableMap(tmpAttributes);
	}

	static final String REG_ID = "REG_ID_TEST";
	static final String REG_ID_JSON = "\"" + REG_ID + "\"";

	static final String SESSION_INDEXES_JSON = "[" + "  \"java.util.Collections$UnmodifiableRandomAccessList\","
			+ "  [ \"Index 1\", \"Index 2\" ]" + "]";
	static final List<String> SESSION_INDEXES = Collections.unmodifiableList(Arrays.asList("Index 1", "Index 2"));

	static final String PRINCIPAL_NAME = "principalName";

	// @formatter:off
	static final String DEFAULT_AUTHENTICATED_PRINCIPAL_JSON = "{"
			+ "  \"@class\": \"org.springframework.security.saml2.provider.service.authentication.DefaultSaml2AuthenticatedPrincipal\","
			+ "  \"name\": \"" + PRINCIPAL_NAME + "\","
			+ "  \"attributes\": {"
			+ "    \"@class\": \"java.util.Collections$UnmodifiableMap\","
			+ "    \"listOf\": ["
			+ "      \"java.util.Collections$UnmodifiableRandomAccessList\","
			+ "      [ \"Element1\", \"Element2\", 4, true ]"
			+ "    ],"
			+ "    \"email\": ["
			+ "      \"java.util.Collections$SingletonList\","
			+ "      [ \"attr_email\" ]"
			+ "    ],"
			+ "    \"name\": ["
			+ "      \"java.util.Collections$SingletonList\","
			+ "      [ \"attr_name\" ]"
			+ "    ]"
			+ "  },"
			+ "  \"sessionIndexes\": " + SESSION_INDEXES_JSON + ","
			+ "  \"registrationId\": " + REG_ID_JSON + ""
			+ "}";
	// @formatter:on

	static DefaultSaml2AuthenticatedPrincipal createDefaultPrincipal() {
		DefaultSaml2AuthenticatedPrincipal principal = new DefaultSaml2AuthenticatedPrincipal(PRINCIPAL_NAME,
				ATTRIBUTES, SESSION_INDEXES);
		principal.setRelyingPartyRegistrationId(REG_ID);
		return principal;
	}

	static final String SAML_REQUEST = "samlRequestValue";
	static final String RELAY_STATE = "relayStateValue";
	static final String AUTHENTICATION_REQUEST_URI = "authenticationRequestUriValue";
	static final String RELYINGPARTY_REGISTRATION_ID = "registrationIdValue";
	static final String SIG_ALG = "sigAlgValue";
	static final String SIGNATURE = "signatureValue";
	static final String ID = "idValue";

	// @formatter:off
	static final String DEFAULT_REDIRECT_AUTH_REQUEST_JSON = "{"
			+ " \"@class\": \"org.springframework.security.saml2.provider.service.authentication.Saml2RedirectAuthenticationRequest\","
			+ " \"samlRequest\": \"" + SAML_REQUEST + "\","
			+ " \"relayState\": \"" + RELAY_STATE + "\","
			+ " \"authenticationRequestUri\": \"" + AUTHENTICATION_REQUEST_URI + "\","
			+ " \"relyingPartyRegistrationId\": \"" + RELYINGPARTY_REGISTRATION_ID + "\","
			+ " \"sigAlg\": \"" + SIG_ALG + "\","
			+ " \"signature\": \"" + SIGNATURE + "\","
			+ " \"id\": \"" + ID + "\""
			+ "}";
	// @formatter:on

	// @formatter:off
	static final String DEFAULT_POST_AUTH_REQUEST_JSON = "{"
			+ " \"@class\": \"org.springframework.security.saml2.provider.service.authentication.Saml2PostAuthenticationRequest\","
			+ " \"samlRequest\": \"" + SAML_REQUEST + "\","
			+ " \"relayState\": \"" + RELAY_STATE + "\","
			+ " \"relyingPartyRegistrationId\": \"" + RELYINGPARTY_REGISTRATION_ID + "\","
			+ " \"authenticationRequestUri\": \"" + AUTHENTICATION_REQUEST_URI + "\","
			+ " \"id\": \"" + ID + "\""
			+ "}";
	// @formatter:on

	static final String LOCATION = "locationValue";
	static final String BINDNG = "REDIRECT";
	static final String ADDITIONAL_PARAM = "additionalParamValue";

	// @formatter:off
	static final String DEFAULT_LOGOUT_REQUEST_JSON = "{"
			+ "  \"@class\": \"org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutRequest\","
			+ "  \"id\": \"" + ID + "\","
			+ "  \"location\": \"" + LOCATION + "\","
			+ "  \"binding\": \"" + BINDNG + "\","
			+ "  \"relyingPartyRegistrationId\": \"" + RELYINGPARTY_REGISTRATION_ID + "\","
			+ "  \"parameters\": { "
			+ "     \"@class\": \"java.util.Collections$UnmodifiableMap\","
			+ "     \"SAMLRequest\": \"" + SAML_REQUEST + "\","
			+ "     \"RelayState\": \"" + RELAY_STATE + "\","
			+ "     \"AdditionalParam\": \"" + ADDITIONAL_PARAM + "\""
			+ "  }"
			+ "}";
	// @formatter:on

	static Saml2PostAuthenticationRequest createDefaultSaml2PostAuthenticationRequest() {
		return Saml2PostAuthenticationRequest.withRelyingPartyRegistration(
				TestRelyingPartyRegistrations.full().registrationId(RELYINGPARTY_REGISTRATION_ID)
						.assertingPartyDetails((party) -> party.singleSignOnServiceLocation(AUTHENTICATION_REQUEST_URI))
						.build())
				.samlRequest(SAML_REQUEST).relayState(RELAY_STATE).id(ID).build();
	}

	static Saml2RedirectAuthenticationRequest createDefaultSaml2RedirectAuthenticationRequest() {
		return Saml2RedirectAuthenticationRequest
				.withRelyingPartyRegistration(TestRelyingPartyRegistrations.full()
						.registrationId(RELYINGPARTY_REGISTRATION_ID)
						.assertingPartyDetails((party) -> party.singleSignOnServiceLocation(AUTHENTICATION_REQUEST_URI))
						.build())
				.samlRequest(SAML_REQUEST).relayState(RELAY_STATE).sigAlg(SIG_ALG).signature(SIGNATURE).id(ID).build();
	}

	static Saml2LogoutRequest createDefaultSaml2LogoutRequest() {
		return Saml2LogoutRequest
				.withRelyingPartyRegistration(
						TestRelyingPartyRegistrations.full().registrationId(RELYINGPARTY_REGISTRATION_ID)
								.assertingPartyDetails((party) -> party.singleLogoutServiceLocation(LOCATION)
										.singleLogoutServiceBinding(Saml2MessageBinding.REDIRECT))
								.build())
				.id(ID).samlRequest(SAML_REQUEST).relayState(RELAY_STATE)
				.parameters((params) -> params.put("AdditionalParam", ADDITIONAL_PARAM)).build();
	}

	static final Collection<GrantedAuthority> AUTHORITIES = Collections
			.unmodifiableList(Arrays.asList(new SimpleGrantedAuthority("Role1"), new SimpleGrantedAuthority("Role2")));

	static final Object DETAILS = User.withUsername("username").password("empty").authorities("A", "B").build();
	static final String SAML_RESPONSE = "samlResponseValue";

	// @formatter:off
	static final String DEFAULT_SAML2AUTHENTICATION_JSON = "{"
			+ "	\"@class\": \"org.springframework.security.saml2.provider.service.authentication.Saml2Authentication\","
			+ "	\"authorities\": ["
			+ "		\"java.util.Collections$UnmodifiableRandomAccessList\","
			+ "		["
			+ "			{"
			+ "				\"@class\": \"org.springframework.security.core.authority.SimpleGrantedAuthority\","
			+ "				\"authority\": \"Role1\""
			+ "			},"
			+ "			{"
			+ "				\"@class\": \"org.springframework.security.core.authority.SimpleGrantedAuthority\","
			+ "				\"authority\": \"Role2\""
			+ "			}"
			+ "		]"
			+ " ],"
			+ "	\"details\": {"
			+ "		\"@class\": \"org.springframework.security.core.userdetails.User\","
			+ "		\"password\": \"empty\","
			+ "		\"username\": \"username\","
			+ "		\"authorities\": ["
			+ "			\"java.util.Collections$UnmodifiableSet\", ["
			+ "				{"
			+ "					\"@class\":\"org.springframework.security.core.authority.SimpleGrantedAuthority\","
			+ "					\"authority\":\"A\""
			+ "				},"
			+ "				{"
			+ "					\"@class\":\"org.springframework.security.core.authority.SimpleGrantedAuthority\","
			+ "					\"authority\":\"B\""
			+ "				}"
			+ "		]],"
			+ "		\"accountNonExpired\": true,"
			+ "		\"accountNonLocked\": true,"
			+ "		\"credentialsNonExpired\": true,"
			+ "		\"enabled\": true"
			+ "	},"
			+ "	\"principal\": " + DEFAULT_AUTHENTICATED_PRINCIPAL_JSON + ","
			+ "	\"saml2Response\": \"" + SAML_RESPONSE + "\""
			+ "}";
	// @formatter:on

	static Saml2Authentication createDefaultAuthentication() {
		DefaultSaml2AuthenticatedPrincipal principal = createDefaultPrincipal();
		Saml2Authentication authentication = new Saml2Authentication(principal, SAML_RESPONSE, AUTHORITIES);
		authentication.setDetails(DETAILS);
		return authentication;
	}

	// @formatter:off
	static final String DEFAULT_SAML_AUTH_EXCEPTION_JSON = "{"
			+ "  \"@class\": \"org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationException\","
			+ "  \"detailMessage\": \"exceptionMessage\","
			+ "  \"error\": {"
			+ "    \"@class\": \"org.springframework.security.saml2.core.Saml2Error\","
			+ "    \"errorCode\": \"errorCode\","
			+ "    \"description\": \"errorDescription\""
			+ "  }"
			+ "}";
	// @formatter:on

	static Saml2AuthenticationException createDefaultSaml2AuthenticationException() {
		return new Saml2AuthenticationException(new Saml2Error("errorCode", "errorDescription"), "exceptionMessage");
	}

}
