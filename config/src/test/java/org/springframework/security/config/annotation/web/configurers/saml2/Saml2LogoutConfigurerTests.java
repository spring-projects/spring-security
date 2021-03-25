/*
 * Copyright 2002-2021 the original author or authors.
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

package org.springframework.security.config.annotation.web.configurers.saml2;

import java.time.Instant;
import java.util.Collection;
import java.util.Collections;
import java.util.function.Consumer;

import javax.servlet.http.HttpServletRequest;

import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.opensaml.saml.saml2.core.LogoutRequest;
import org.opensaml.xmlsec.signature.support.SignatureConstants;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.test.SpringTestRule;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.saml2.Saml2Exception;
import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.security.saml2.core.TestSaml2X509Credentials;
import org.springframework.security.saml2.provider.service.authentication.DefaultSaml2AuthenticatedPrincipal;
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication;
import org.springframework.security.saml2.provider.service.authentication.TestOpenSamlObjects;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutRequest;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutResponse;
import org.springframework.security.saml2.provider.service.registration.InMemoryRelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.TestRelyingPartyRegistrations;
import org.springframework.security.saml2.provider.service.web.authentication.logout.HttpSessionLogoutRequestRepository;
import org.springframework.security.saml2.provider.service.web.authentication.logout.Saml2LogoutRequestRepository;
import org.springframework.security.saml2.provider.service.web.authentication.logout.Saml2LogoutRequestResolver;
import org.springframework.security.saml2.provider.service.web.authentication.logout.Saml2LogoutResponseResolver;
import org.springframework.security.saml2.provider.service.web.authentication.logout.Saml2LogoutResponseResolver.Saml2LogoutResponseBuilder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.RETURNS_SELF;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.mock;
import static org.mockito.BDDMockito.reset;
import static org.mockito.BDDMockito.verify;
import static org.mockito.BDDMockito.verifyNoInteractions;
import static org.mockito.BDDMockito.willAnswer;
import static org.mockito.BDDMockito.willReturn;
import static org.springframework.security.config.Customizer.withDefaults;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Tests for different Java configuration for {@link Saml2LogoutConfigurer}
 */
public class Saml2LogoutConfigurerTests {

	@Autowired
	private ConfigurableApplicationContext context;

	@Autowired
	private RelyingPartyRegistrationRepository repository;

	private final Saml2LogoutRequestRepository logoutRequestRepository = new HttpSessionLogoutRequestRepository();

	@Rule
	public final SpringTestRule spring = new SpringTestRule();

	@Autowired(required = false)
	MockMvc mvc;

	private Saml2Authentication user = new Saml2Authentication(
			new DefaultSaml2AuthenticatedPrincipal("user", Collections.emptyMap()), "response",
			AuthorityUtils.createAuthorityList("ROLE_USER"), "registration-id");

	String apLogoutRequest = "nZFBa4MwGIb/iuQeE2NTXFDLQAaC26Hrdtgt1dQFNMnyxdH9+zlboeyww275SN7nzcOX787jEH0qD9qaAiUxRZEyre206Qv0cnjAGdqVOchxYE40trdT2KuPSUGI5qQBcbkq0OSNsBI0CCNHBSK04vn+sREspsJ5G2xrBxRVc1AbGZa29xAcCEK8i9VZjm5QsfU9GZYWsoCJv5ShqK4K1Ow5p5LyU4aP6XaLN3cpw9mGctydjrxNaZt1XM5vASZVGwjShAIxyhJMU8z4gSWCM8GSmDH+hqLX1Xv+JLpaiiXsb+3+lpMAyv8IoVI6rEzQ4QvrLie3uBX+NMfr6l/waT6t0AumvI6/FlN+Aw==";

	String apLogoutRequestSigAlg = SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256;

	String apLogoutRequestRelayState = "33591874-b123-4f2c-ab0d-2d0d84aa8b56";

	String apLogoutRequestSignature = "oKqdzrmn2YAqXcwkow2lzRXr5PNHm0s/gWsRnaZYhC+Oq5ekK5uIKQYvtmNR94HJjDe1VRs+vVQCYivgdoTzBV2ZlffTXZmYsCsY9q4jbCWR6R5CbhU73/MkKQsPcyVvMhNYxnDYapIlxDsfoZNTboDEz3GM+HRoGRfl9emCXY0lPRYwqC4kpu7oMDBkafR0A09jPIxFuNpqlLPwUxL9m+DGkvDK3mFDN1xJcgZaK73HcuJe7Qh4huOrKNFetwc5EvqfiwgiWF6sfq9A+rZBfCIYo10NNLY7fNQAR2IqwcKtawHgTGWbeshRyFrwVYMR64EnClfxUHsHKf5kiZ2dlw==";

	String apLogoutResponse = "fZHRa4MwEMb/Fcl7jEadGqplrAwK3Uvb9WFvZ4ydoInk4uj++1nXbmWMvhwcd9/3Jb9bLE99530oi63RBQn9gHhKS1O3+liQ1/0zzciyXCD0HR/ExhzN6LYKB6NReZNUo/ieFWS0WhjAFoWGXqFwUuweXzaC+4EYrHFGmo54K4Wu1eDmuHfnBhSM2cFXJ+iHTvnGHlk3x7DZmNlLGvHWq4Jstk0GUSjjiIZJI2lcpQnNeRLTAOo4fwCeQg3Trr6+cm/OqmnWVHECVGWQ0jgCSatsKvXUxhFvZF7xSYU4qrVGB9oVhAc8pEFEebLnkeBc8NyPePpGvMOV1/Q3cqEjZrG9hXKfCSAqe+ZAShio0q51n7StF+zW7gf9zoEb8U/7ZGrlHaAb1f0onLfFbpRSIRJWXkJ+bdm/Fy6/AA==";

	String apLogoutResponseSigAlg = SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256;

	String apLogoutResponseRelayState = "8f63887a-ec7e-4149-b6a0-dd730017f315";

	String apLogoutResponseSignature = "h2fDqSIBfmnkRHKDMY4IxkCXcI0w98ydNsnPmv1b7GTZCWLbJ+oxaP2yZNPw7wOWXTv86cTPwKLjx5halKy5C+hhWnT0haKhuMcUvHlsgAMBbJKLV+1afzL4O77cvAQJmMNRK7ugXGNV5PTEnd1U4voy134OgdD5XycYiFVRZOwP5H84eJ9xxlvqQwqDvZTcgiF/ZS4ioZgzgnIFcbagZQ12LWNh26OMaUpIW04kCeO6t2dUsxOL6nZWvNrX/Zx1sORIpu4doDUa1RYC8YnjZeQEzDqUVC/dBO/mbVJ/hbF9tD0jBUx7YIgoXpqsWK4TcCsvmlmhrJXvGxDyoAWu2Q==";

	String rpLogoutRequest = "nZFBa4MwGIb/iuQeY6NlGtQykIHgdui6HXaLmrqAJlm+OLp/v0wrlB122CXkI3mfNw/JD5dpDD6FBalVgXZhhAKhOt1LNRTo5fSAU3Qoc+DTSA1r9KBndxQfswAX+KQCth4VaLaKaQ4SmOKTAOY69nz/2DAaRsxY7XSnRxRUPigVd0vbu3MGGCHchOLCJzOKUNuBjEsLWcDErmUoqKsCNcc+yc5tsudYpPwOJzHvcJv6pfdjEtNzl7XU3wWYRa3AceUKRCO6w1GM6f5EY0Ypo1lIk+gNBa+bt38kulqyJWxv7f6W4wDC/gih0hoslJPuC8s+J7e4Df7k43X1L/jsdxt0xZTX8dfHlN8=";

	String rpLogoutRequestId = "LRd49fb45a-e8a7-43ac-b8ac-d8a7432fc9b2";

	String rpLogoutRequestRelayState = "8f63887a-ec7e-4149-b6a0-dd730017f315";

	String rpLogoutRequestSignature = "h2fDqSIBfmnkRHKDMY4IxkCXcI0w98ydNsnPmv1b7GTZCWLbJ+oxaP2yZNPw7wOWXTv86cTPwKLjx5halKy5C+hhWnT0haKhuMcUvHlsgAMBbJKLV+1afzL4O77cvAQJmMNRK7ugXGNV5PTEnd1U4voy134OgdD5XycYiFVRZOwP5H84eJ9xxlvqQwqDvZTcgiF/ZS4ioZgzgnIFcbagZQ12LWNh26OMaUpIW04kCeO6t2dUsxOL6nZWvNrX/Zx1sORIpu4doDUa1RYC8YnjZeQEzDqUVC/dBO/mbVJ/hbF9tD0jBUx7YIgoXpqsWK4TcCsvmlmhrJXvGxDyoAWu2Q==";

	private MockHttpServletRequest request;

	private MockHttpServletResponse response;

	private MockFilterChain filterChain;

	@Before
	public void setup() {
		this.request = new MockHttpServletRequest("POST", "");
		this.request.setServletPath("/login/saml2/sso/test-rp");
		this.response = new MockHttpServletResponse();
		this.filterChain = new MockFilterChain();
	}

	@After
	public void cleanup() {
		if (this.context != null) {
			this.context.close();
		}
		reset(Saml2LogoutDefaultsConfig.mockLogoutHandler);
	}

	@Test
	public void saml2LogoutWhenDefaultsThenLogsOutAndSendsLogoutRequest() throws Exception {
		this.spring.register(Saml2LogoutDefaultsConfig.class).autowire();
		MvcResult result = this.mvc.perform(post("/logout").with(authentication(this.user)).with(csrf()))
				.andExpect(status().isFound()).andReturn();
		String location = result.getResponse().getHeader("Location");
		assertThat(location).startsWith("https://ap.example.org/logout/saml2/request");
		verify(Saml2LogoutDefaultsConfig.mockLogoutHandler).logout(any(), any(), any());
	}

	@Test
	public void saml2LogoutWhenUnauthenticatedThenEntryPoint() throws Exception {
		this.spring.register(Saml2LogoutDefaultsConfig.class).autowire();
		this.mvc.perform(post("/logout").with(csrf())).andExpect(status().isFound())
				.andExpect(redirectedUrl("/login?logout"));
	}

	@Test
	public void saml2LogoutWhenMissingCsrfThen403() throws Exception {
		this.spring.register(Saml2LogoutDefaultsConfig.class).autowire();
		this.mvc.perform(post("/logout").with(authentication(this.user))).andExpect(status().isForbidden());
		verifyNoInteractions(Saml2LogoutDefaultsConfig.mockLogoutHandler);
	}

	@Test
	public void saml2LogoutWhenGetThenDefaultLogoutPage() throws Exception {
		this.spring.register(Saml2LogoutDefaultsConfig.class).autowire();
		MvcResult result = this.mvc.perform(get("/logout").with(authentication(this.user)).with(csrf()))
				.andExpect(status().isOk()).andReturn();
		assertThat(result.getResponse().getContentAsString()).contains("Are you sure you want to log out?");
		verifyNoInteractions(Saml2LogoutDefaultsConfig.mockLogoutHandler);
	}

	@Test
	public void saml2LogoutWhenPutOrDeleteThen404() throws Exception {
		this.spring.register(Saml2LogoutDefaultsConfig.class).autowire();
		this.mvc.perform(put("/logout").with(authentication(this.user)).with(csrf())).andExpect(status().isNotFound());
		this.mvc.perform(delete("/logout").with(authentication(this.user)).with(csrf()))
				.andExpect(status().isNotFound());
		verifyNoInteractions(Saml2LogoutDefaultsConfig.mockLogoutHandler);
	}

	@Test
	public void saml2LogoutWhenNoRegistrationThenIllegalArgument() {
		this.spring.register(Saml2LogoutDefaultsConfig.class).autowire();
		Saml2Authentication authentication = new Saml2Authentication(
				new DefaultSaml2AuthenticatedPrincipal("user", Collections.emptyMap()), "response",
				AuthorityUtils.createAuthorityList("ROLE_USER"), "wrong");
		assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(
				() -> this.mvc.perform(post("/logout").with(authentication(authentication)).with(csrf())).andReturn());
	}

	@Test
	public void saml2LogoutWhenCustomLogoutRequestResolverThenUses() throws Exception {
		this.spring.register(Saml2LogoutComponentsConfig.class).autowire();
		this.mvc.perform(post("/logout").with(authentication(this.user)).with(csrf()));
		verify(Saml2LogoutComponentsConfig.logoutRequestResolver).resolveLogoutRequest(any(), any());
	}

	@Test
	public void saml2LogoutRequestWhenDefaultsThenLogsOutAndSendsLogoutResponse() throws Exception {
		this.spring.register(Saml2LogoutDefaultsConfig.class).autowire();
		MvcResult result = this.mvc
				.perform(get("/logout/saml2/slo").param("SAMLRequest", this.apLogoutRequest)
						.param("RelayState", this.apLogoutRequestRelayState).param("SigAlg", this.apLogoutRequestSigAlg)
						.param("Signature", this.apLogoutRequestSignature).with(authentication(this.user)))
				.andExpect(status().isFound()).andReturn();
		String location = result.getResponse().getHeader("Location");
		assertThat(location).startsWith("https://ap.example.org/logout/saml2/response");
		verify(Saml2LogoutDefaultsConfig.mockLogoutHandler).logout(any(), any(), any());
	}

	@Test
	public void saml2LogoutRequestWhenNoRegistrationThenIllegalArgument() throws Exception {
		this.spring.register(Saml2LogoutDefaultsConfig.class).autowire();
		assertThatExceptionOfType(IllegalArgumentException.class)
				.isThrownBy(() -> this.mvc.perform(get("/logout/saml2/slo").param("SAMLRequest", this.apLogoutRequest)
						.param("RelayState", this.apLogoutRequestRelayState).param("SigAlg", this.apLogoutRequestSigAlg)
						.param("Signature", this.apLogoutRequestSignature)).andReturn());
		verifyNoInteractions(Saml2LogoutDefaultsConfig.mockLogoutHandler);
	}

	@Test
	public void saml2LogoutRequestWhenNoSamlRequestThen404() throws Exception {
		this.spring.register(Saml2LogoutDefaultsConfig.class).autowire();
		this.mvc.perform(get("/logout/saml2/slo").with(authentication(this.user))).andExpect(status().isNotFound());
		verifyNoInteractions(Saml2LogoutDefaultsConfig.mockLogoutHandler);
	}

	@Test
	public void saml2LogoutRequestWhenInvalidSamlRequestThenException() throws Exception {
		this.spring.register(Saml2LogoutDefaultsConfig.class).autowire();
		assertThatExceptionOfType(Saml2Exception.class)
				.isThrownBy(() -> this.mvc
						.perform(get("/logout/saml2/slo").param("SAMLRequest", this.apLogoutRequest)
								.param("RelayState", this.apLogoutRequestRelayState)
								.param("SigAlg", this.apLogoutRequestSigAlg).with(authentication(this.user)))
						.andReturn());
		verifyNoInteractions(Saml2LogoutDefaultsConfig.mockLogoutHandler);
	}

	@Test
	public void saml2LogoutRequestWhenCustomLogoutRequestHandlerThenUses() throws Exception {
		this.spring.register(Saml2LogoutComponentsConfig.class).autowire();
		RelyingPartyRegistration registration = this.repository.findByRegistrationId("registration-id");
		LogoutRequest logoutRequest = TestOpenSamlObjects.assertingPartyLogoutRequest(registration);
		logoutRequest.setIssueInstant(Instant.now());
		willAnswer((invocation) -> {
			HttpServletRequest request = (HttpServletRequest) invocation.getArguments()[0];
			request.setAttribute(LogoutRequest.class.getName(), logoutRequest);
			return null;
		}).given(Saml2LogoutComponentsConfig.logoutRequestHandler).logout(any(), any(), any());
		Saml2LogoutResponseBuilder<?> partial = mock(Saml2LogoutResponseBuilder.class, RETURNS_SELF);
		given(partial.logoutResponse())
				.willReturn(Saml2LogoutResponse.withRelyingPartyRegistration(registration).build());
		willReturn(partial).given(Saml2LogoutComponentsConfig.logoutResponseResolver).resolveLogoutResponse(any(),
				any());
		this.mvc.perform(get("/logout/saml2/slo").param("SAMLRequest", "samlRequest")).andReturn();
		verify(Saml2LogoutComponentsConfig.logoutRequestHandler).logout(any(), any(), any());
		verify(Saml2LogoutComponentsConfig.logoutResponseResolver).resolveLogoutResponse(any(), any());
	}

	@Test
	public void saml2LogoutResponseWhenDefaultsThenRedirectsAndDoesNotLogout() throws Exception {
		this.spring.register(Saml2LogoutDefaultsConfig.class).autowire();
		RelyingPartyRegistration registration = this.repository.findByRegistrationId("registration-id");
		Saml2LogoutRequest logoutRequest = Saml2LogoutRequest.withRelyingPartyRegistration(registration)
				.samlRequest(this.rpLogoutRequest).id(this.rpLogoutRequestId).relayState(this.rpLogoutRequestRelayState)
				.parameters((params) -> params.put("Signature", this.rpLogoutRequestSignature)).build();
		this.logoutRequestRepository.saveLogoutRequest(logoutRequest, this.request, this.response);
		this.request.setParameter("RelayState", logoutRequest.getRelayState());
		assertThat(this.logoutRequestRepository.loadLogoutRequest(this.request)).isNotNull();
		this.mvc.perform(get("/logout/saml2/slo").session(((MockHttpSession) this.request.getSession()))
				.param("SAMLResponse", this.apLogoutResponse).param("RelayState", this.apLogoutResponseRelayState)
				.param("SigAlg", this.apLogoutResponseSigAlg).param("Signature", this.apLogoutResponseSignature))
				.andExpect(status().isFound()).andExpect(redirectedUrl("/login?logout"));
		verifyNoInteractions(Saml2LogoutDefaultsConfig.mockLogoutHandler);
		assertThat(this.logoutRequestRepository.loadLogoutRequest(this.request)).isNull();
	}

	@Test
	public void saml2LogoutResponseWhenNoMatchingLogoutRequestThenSaml2Exception() throws Exception {
		this.spring.register(Saml2LogoutDefaultsConfig.class).autowire();
		assertThatExceptionOfType(Saml2Exception.class).isThrownBy(() -> this.mvc.perform(get("/logout/saml2/slo")
				.param("SAMLResponse", this.apLogoutResponse).param("RelayState", this.apLogoutResponseRelayState)
				.param("SigAlg", this.apLogoutResponseSigAlg).param("Signature", this.apLogoutResponseSignature)));
		verifyNoInteractions(Saml2LogoutDefaultsConfig.mockLogoutHandler);
	}

	@Test
	public void saml2LogoutResponseWhenNoSamlResponseThenEntryPoint() throws Exception {
		this.spring.register(Saml2LogoutDefaultsConfig.class).autowire();
		this.mvc.perform(get("/logout/saml2/slo")).andExpect(status().isFound())
				.andExpect(redirectedUrl("http://localhost/login"));
		verifyNoInteractions(Saml2LogoutDefaultsConfig.mockLogoutHandler);
	}

	@Test
	public void saml2LogoutResponseWhenInvalidSamlResponseThenException() {
		this.spring.register(Saml2LogoutDefaultsConfig.class).autowire();
		RelyingPartyRegistration registration = this.repository.findByRegistrationId("registration-id");
		Saml2LogoutRequest logoutRequest = Saml2LogoutRequest.withRelyingPartyRegistration(registration)
				.samlRequest(this.rpLogoutRequest).id(this.rpLogoutRequestId).relayState(this.rpLogoutRequestRelayState)
				.parameters((params) -> params.put("Signature", this.rpLogoutRequestSignature)).build();
		this.logoutRequestRepository.saveLogoutRequest(logoutRequest, this.request, this.response);
		assertThatExceptionOfType(Saml2Exception.class).isThrownBy(
				() -> this.mvc.perform(get("/logout/saml2/slo").session((MockHttpSession) this.request.getSession())
						.param("SAMLResponse", this.apLogoutRequest).param("RelayState", this.apLogoutRequestRelayState)
						.param("SigAlg", this.apLogoutRequestSigAlg)).andReturn());
		verifyNoInteractions(Saml2LogoutDefaultsConfig.mockLogoutHandler);
	}

	@Test
	public void saml2LogoutResponseWhenCustomLogoutResponseHandlerThenUses() throws Exception {
		this.spring.register(Saml2LogoutComponentsConfig.class).autowire();
		this.mvc.perform(get("/logout/saml2/slo").param("SAMLResponse", "samlResponse")).andReturn();
		verify(Saml2LogoutComponentsConfig.logoutResponseHandler).logout(any(), any(), any());
	}

	@EnableWebSecurity
	@Import(Saml2LoginConfigBeans.class)
	static class Saml2LogoutDefaultsConfig {

		static final LogoutHandler mockLogoutHandler = mock(LogoutHandler.class);

		@Bean
		SecurityFilterChain web(HttpSecurity http) throws Exception {
			http.authorizeRequests((authorize) -> authorize.anyRequest().authenticated()).saml2Login(withDefaults())
					.saml2Logout((logout) -> logout.addLogoutHandler(mockLogoutHandler));
			return http.build();
		}

	}

	@EnableWebSecurity
	@Import(Saml2LoginConfigBeans.class)
	static class Saml2LogoutComponentsConfig {

		static final Saml2LogoutRequestRepository logoutRequestRepository = mock(Saml2LogoutRequestRepository.class);
		static final LogoutHandler logoutRequestHandler = mock(LogoutHandler.class);
		static final Saml2LogoutRequestResolver logoutRequestResolver = mock(Saml2LogoutRequestResolver.class);
		static final LogoutHandler logoutResponseHandler = mock(LogoutHandler.class);
		static final Saml2LogoutResponseResolver logoutResponseResolver = mock(Saml2LogoutResponseResolver.class);

		@Bean
		SecurityFilterChain web(HttpSecurity http) throws Exception {
			http.authorizeRequests((authorize) -> authorize.anyRequest().authenticated()).saml2Login(withDefaults())
					.saml2Logout((logout) -> logout
							.logoutRequest((request) -> request.logoutRequestRepository(logoutRequestRepository)
									.logoutRequestHandler(logoutRequestHandler)
									.logoutRequestResolver(logoutRequestResolver))
							.logoutResponse((response) -> response.logoutResponseHandler(logoutResponseHandler)
									.logoutResponseResolver(logoutResponseResolver)));
			return http.build();
		}

	}

	static class Saml2LoginConfigBeans {

		@Bean
		RelyingPartyRegistrationRepository relyingPartyRegistrationRepository() {
			Saml2X509Credential signing = TestSaml2X509Credentials.assertingPartySigningCredential();
			Saml2X509Credential verification = TestSaml2X509Credentials.relyingPartyVerifyingCredential();
			RelyingPartyRegistration.Builder withCreds = TestRelyingPartyRegistrations.noCredentials()
					.signingX509Credentials(credential(signing))
					.assertingPartyDetails((party) -> party.verificationX509Credentials(credential(verification)));
			RelyingPartyRegistration registration = withCreds.build();
			RelyingPartyRegistration ap = withCreds.registrationId("ap").entityId("ap-entity-id")
					.assertingPartyDetails((party) -> party
							.singleLogoutServiceLocation("https://rp.example.org/logout/saml2/request")
							.singleLogoutServiceResponseLocation("https://rp.example.org/logout/saml2/response"))
					.build();

			return new InMemoryRelyingPartyRegistrationRepository(ap, registration);
		}

		private Consumer<Collection<Saml2X509Credential>> credential(Saml2X509Credential credential) {
			return (credentials) -> credentials.add(credential);
		}

	}

}
