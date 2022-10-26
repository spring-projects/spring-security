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

package org.springframework.security.config.annotation.web.configurers.saml2;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Collection;
import java.util.Collections;
import java.util.Map;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.opensaml.saml.saml2.core.LogoutRequest;
import org.opensaml.xmlsec.signature.support.SignatureConstants;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.SecurityContextChangedListenerConfig;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.test.SpringTestContext;
import org.springframework.security.config.test.SpringTestContextExtension;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.saml2.core.Saml2Utils;
import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.security.saml2.core.TestSaml2X509Credentials;
import org.springframework.security.saml2.provider.service.authentication.DefaultSaml2AuthenticatedPrincipal;
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication;
import org.springframework.security.saml2.provider.service.authentication.TestOpenSamlObjects;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutRequest;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutRequestValidator;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutResponse;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutResponseValidator;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutValidatorResult;
import org.springframework.security.saml2.provider.service.registration.InMemoryRelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.Saml2MessageBinding;
import org.springframework.security.saml2.provider.service.registration.TestRelyingPartyRegistrations;
import org.springframework.security.saml2.provider.service.web.authentication.logout.HttpSessionLogoutRequestRepository;
import org.springframework.security.saml2.provider.service.web.authentication.logout.Saml2LogoutRequestFilter;
import org.springframework.security.saml2.provider.service.web.authentication.logout.Saml2LogoutRequestRepository;
import org.springframework.security.saml2.provider.service.web.authentication.logout.Saml2LogoutRequestResolver;
import org.springframework.security.saml2.provider.service.web.authentication.logout.Saml2LogoutResponseFilter;
import org.springframework.security.saml2.provider.service.web.authentication.logout.Saml2LogoutResponseResolver;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.RequestPostProcessor;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.UriUtils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.mock;
import static org.mockito.BDDMockito.verify;
import static org.mockito.BDDMockito.verifyNoInteractions;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.spy;
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
@ExtendWith(SpringTestContextExtension.class)
public class Saml2LogoutConfigurerTests {

	@Autowired
	private ConfigurableApplicationContext context;

	@Autowired
	private RelyingPartyRegistrationRepository repository;

	private final Saml2LogoutRequestRepository logoutRequestRepository = new HttpSessionLogoutRequestRepository();

	public final SpringTestContext spring = new SpringTestContext(this);

	@Autowired(required = false)
	MockMvc mvc;

	private Saml2Authentication user;

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

	@BeforeEach
	public void setup() {
		DefaultSaml2AuthenticatedPrincipal principal = new DefaultSaml2AuthenticatedPrincipal("user",
				Collections.emptyMap());
		principal.setRelyingPartyRegistrationId("registration-id");
		this.user = new Saml2Authentication(principal, "response", AuthorityUtils.createAuthorityList("ROLE_USER"));
		this.request = new MockHttpServletRequest("POST", "");
		this.request.setServletPath("/login/saml2/sso/test-rp");
		this.response = new MockHttpServletResponse();
	}

	@AfterEach
	public void cleanup() {
		if (this.context != null) {
			this.context.close();
		}
	}

	@Test
	public void logoutWhenDefaultsAndNotSaml2LoginThenDefaultLogout() throws Exception {
		this.spring.register(Saml2LogoutDefaultsConfig.class).autowire();
		TestingAuthenticationToken user = new TestingAuthenticationToken("user", "password");
		MvcResult result = this.mvc.perform(post("/logout").with(authentication(user)).with(csrf()))
				.andExpect(status().isFound()).andReturn();
		String location = result.getResponse().getHeader("Location");
		LogoutHandler logoutHandler = this.spring.getContext().getBean(LogoutHandler.class);
		assertThat(location).isEqualTo("/login?logout");
		verify(logoutHandler).logout(any(), any(), any());
	}

	@Test
	public void saml2LogoutWhenDefaultsThenLogsOutAndSendsLogoutRequest() throws Exception {
		this.spring.register(Saml2LogoutDefaultsConfig.class).autowire();
		MvcResult result = this.mvc.perform(post("/logout").with(authentication(this.user)).with(csrf()))
				.andExpect(status().isFound()).andReturn();
		String location = result.getResponse().getHeader("Location");
		LogoutHandler logoutHandler = this.spring.getContext().getBean(LogoutHandler.class);
		assertThat(location).startsWith("https://ap.example.org/logout/saml2/request");
		verify(logoutHandler).logout(any(), any(), any());
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
		verifyNoInteractions(getBean(LogoutHandler.class));
	}

	@Test
	public void saml2LogoutWhenGetThenDefaultLogoutPage() throws Exception {
		this.spring.register(Saml2LogoutDefaultsConfig.class).autowire();
		MvcResult result = this.mvc.perform(get("/logout").with(authentication(this.user))).andExpect(status().isOk())
				.andReturn();
		assertThat(result.getResponse().getContentAsString()).contains("Are you sure you want to log out?");
		verifyNoInteractions(getBean(LogoutHandler.class));
	}

	@Test
	public void saml2LogoutWhenPutOrDeleteThen404() throws Exception {
		this.spring.register(Saml2LogoutDefaultsConfig.class).autowire();
		this.mvc.perform(put("/logout").with(authentication(this.user)).with(csrf())).andExpect(status().isNotFound());
		this.mvc.perform(delete("/logout").with(authentication(this.user)).with(csrf()))
				.andExpect(status().isNotFound());
		verifyNoInteractions(this.spring.getContext().getBean(LogoutHandler.class));
	}

	@Test
	public void saml2LogoutWhenNoRegistrationThen401() throws Exception {
		this.spring.register(Saml2LogoutDefaultsConfig.class).autowire();
		DefaultSaml2AuthenticatedPrincipal principal = new DefaultSaml2AuthenticatedPrincipal("user",
				Collections.emptyMap());
		principal.setRelyingPartyRegistrationId("wrong");
		Saml2Authentication authentication = new Saml2Authentication(principal, "response",
				AuthorityUtils.createAuthorityList("ROLE_USER"));
		this.mvc.perform(post("/logout").with(authentication(authentication)).with(csrf()))
				.andExpect(status().isUnauthorized());
	}

	@Test
	public void saml2LogoutWhenCsrfDisabledAndNoAuthenticationThenFinalRedirect() throws Exception {
		this.spring.register(Saml2LogoutCsrfDisabledConfig.class).autowire();
		this.mvc.perform(post("/logout"));
		LogoutSuccessHandler logoutSuccessHandler = this.spring.getContext().getBean(LogoutSuccessHandler.class);
		verify(logoutSuccessHandler).onLogoutSuccess(any(), any(), any());
	}

	@Test
	public void saml2LogoutWhenCustomLogoutRequestResolverThenUses() throws Exception {
		this.spring.register(Saml2LogoutComponentsConfig.class).autowire();
		RelyingPartyRegistration registration = this.repository.findByRegistrationId("registration-id");
		Saml2LogoutRequest logoutRequest = Saml2LogoutRequest.withRelyingPartyRegistration(registration)
				.samlRequest(this.rpLogoutRequest).id(this.rpLogoutRequestId).relayState(this.rpLogoutRequestRelayState)
				.parameters((params) -> params.put("Signature", this.rpLogoutRequestSignature)).build();
		given(getBean(Saml2LogoutRequestResolver.class).resolve(any(), any())).willReturn(logoutRequest);
		this.mvc.perform(post("/logout").with(authentication(this.user)).with(csrf()));
		verify(getBean(Saml2LogoutRequestResolver.class)).resolve(any(), any());
	}

	@Test
	public void saml2LogoutRequestWhenDefaultsThenLogsOutAndSendsLogoutResponse() throws Exception {
		this.spring.register(Saml2LogoutDefaultsConfig.class).autowire();
		DefaultSaml2AuthenticatedPrincipal principal = new DefaultSaml2AuthenticatedPrincipal("user",
				Collections.emptyMap());
		principal.setRelyingPartyRegistrationId("get");
		Saml2Authentication user = new Saml2Authentication(principal, "response",
				AuthorityUtils.createAuthorityList("ROLE_USER"));
		MvcResult result = this.mvc.perform(get("/logout/saml2/slo").param("SAMLRequest", this.apLogoutRequest)
				.param("RelayState", this.apLogoutRequestRelayState).param("SigAlg", this.apLogoutRequestSigAlg)
				.param("Signature", this.apLogoutRequestSignature).with(samlQueryString()).with(authentication(user)))
				.andExpect(status().isFound()).andReturn();
		String location = result.getResponse().getHeader("Location");
		assertThat(location).startsWith("https://ap.example.org/logout/saml2/response");
		verify(getBean(LogoutHandler.class)).logout(any(), any(), any());
	}

	@Test
	public void saml2LogoutRequestWhenCustomSecurityContextHolderStrategyThenUses() throws Exception {
		this.spring.register(Saml2LogoutDefaultsConfig.class, SecurityContextChangedListenerConfig.class).autowire();
		DefaultSaml2AuthenticatedPrincipal principal = new DefaultSaml2AuthenticatedPrincipal("user",
				Collections.emptyMap());
		principal.setRelyingPartyRegistrationId("get");
		Saml2Authentication user = new Saml2Authentication(principal, "response",
				AuthorityUtils.createAuthorityList("ROLE_USER"));
		MvcResult result = this.mvc.perform(get("/logout/saml2/slo").param("SAMLRequest", this.apLogoutRequest)
				.param("RelayState", this.apLogoutRequestRelayState).param("SigAlg", this.apLogoutRequestSigAlg)
				.param("Signature", this.apLogoutRequestSignature).with(samlQueryString()).with(authentication(user)))
				.andExpect(status().isFound()).andReturn();
		String location = result.getResponse().getHeader("Location");
		assertThat(location).startsWith("https://ap.example.org/logout/saml2/response");
		verify(getBean(LogoutHandler.class)).logout(any(), any(), any());
		verify(getBean(SecurityContextHolderStrategy.class), atLeastOnce()).getContext();
	}

	// gh-11235
	@Test
	public void saml2LogoutRequestWhenLowercaseEncodingThenLogsOutAndSendsLogoutResponse() throws Exception {
		this.spring.register(Saml2LogoutDefaultsConfig.class).autowire();
		String apLogoutRequest = "nZFNa4QwEIb/iuQeP6K7dYO6FKQg2B622x56G3WwgiY2E8v239fqCksPPfSWIXmfNw+THC9D73yi\r\n"
				+ "oU6rlAWuzxxUtW461abs5fzAY3bMEoKhF6Msdasne8KPCck6c1KRXK9SNhklNVBHUsGAJG0tn+8f\r\n"
				+ "SylcX45GW13rnjn5HOwU2KXt3dqRpOeZ0cULDGOPrjat1y8t3gL2zFrGnCJPWXkKcR8KCHY8xmrP\r\n"
				+ "Iz868OpOVLwO4wohggagmd8STVgosqBsyoQvBPd3XITnIJaRL8PYjcThjTmvm/f8SXa1lEvY3Nr9\r\n"
				+ "LQdEaH6EWAYjR2U7+8W7JvFucRv8aY4X+b/g03zaoCsmu46/FpN9Aw==";
		String apLogoutRequestRelayState = "d118dbd5-3853-4268-b3e5-c40fc033fa2f";
		String apLogoutRequestSignature = "VZ7rWa5u3hIX60fAQs/gBQZWDP2BAIlCMMrNrTHafoKKj0uXWnuITYLuL8NdsWmyQN0+fqWW4X05+BqiLpL80jHLmQR5RVqqL1EtVv1SpPUna938lgz2sOliuYmfQNj4Bmd+Z5G1K6QhbVrtfb7TQHURjUafzfRm8+jGz3dPjVBrn/rD/umfGoSn6RuWngugcMNL4U0A+JcEh1NSfSYNVz7y+MqlW1UhX2kF86rm97ERCrxay7Gh/bI2f3fJPJ1r+EyLjzrDUkqw5cva3rVlFgEQouMVu35lUJn7SFompW8oTxkI23oc/t+AGZqaBupNITNdjyGCBpfukZ69EZrj8g==";
		DefaultSaml2AuthenticatedPrincipal principal = new DefaultSaml2AuthenticatedPrincipal("user",
				Collections.emptyMap());
		principal.setRelyingPartyRegistrationId("get");
		Saml2Authentication user = new Saml2Authentication(principal, "response",
				AuthorityUtils.createAuthorityList("ROLE_USER"));
		MvcResult result = this.mvc
				.perform(get("/logout/saml2/slo").param("SAMLRequest", apLogoutRequest)
						.param("RelayState", apLogoutRequestRelayState).param("SigAlg", this.apLogoutRequestSigAlg)
						.param("Signature", apLogoutRequestSignature)
						.with(new SamlQueryStringRequestPostProcessor(true)).with(authentication(user)))
				.andExpect(status().isFound()).andReturn();
		String location = result.getResponse().getHeader("Location");
		assertThat(location).startsWith("https://ap.example.org/logout/saml2/response");
		verify(getBean(LogoutHandler.class)).logout(any(), any(), any());
	}

	@Test
	public void saml2LogoutRequestWhenNoRegistrationThen400() throws Exception {
		this.spring.register(Saml2LogoutDefaultsConfig.class).autowire();
		DefaultSaml2AuthenticatedPrincipal principal = new DefaultSaml2AuthenticatedPrincipal("user",
				Collections.emptyMap());
		principal.setRelyingPartyRegistrationId("wrong");
		Saml2Authentication user = new Saml2Authentication(principal, "response",
				AuthorityUtils.createAuthorityList("ROLE_USER"));
		this.mvc.perform(get("/logout/saml2/slo").param("SAMLRequest", this.apLogoutRequest)
				.param("RelayState", this.apLogoutRequestRelayState).param("SigAlg", this.apLogoutRequestSigAlg)
				.param("Signature", this.apLogoutRequestSignature).with(authentication(user)))
				.andExpect(status().isBadRequest());
		verifyNoInteractions(getBean(LogoutHandler.class));
	}

	@Test
	public void saml2LogoutRequestWhenInvalidSamlRequestThen401() throws Exception {
		this.spring.register(Saml2LogoutDefaultsConfig.class).autowire();
		this.mvc.perform(get("/logout/saml2/slo").param("SAMLRequest", this.apLogoutRequest)
				.param("RelayState", this.apLogoutRequestRelayState).param("SigAlg", this.apLogoutRequestSigAlg)
				.with(authentication(this.user))).andExpect(status().isUnauthorized());
		verifyNoInteractions(getBean(LogoutHandler.class));
	}

	@Test
	public void saml2LogoutRequestWhenCustomLogoutRequestHandlerThenUses() throws Exception {
		this.spring.register(Saml2LogoutComponentsConfig.class).autowire();
		RelyingPartyRegistration registration = this.repository.findByRegistrationId("registration-id");
		LogoutRequest logoutRequest = TestOpenSamlObjects.assertingPartyLogoutRequest(registration);
		logoutRequest.setIssueInstant(Instant.now());
		given(getBean(Saml2LogoutRequestValidator.class).validate(any()))
				.willReturn(Saml2LogoutValidatorResult.success());
		Saml2LogoutResponse logoutResponse = Saml2LogoutResponse.withRelyingPartyRegistration(registration).build();
		given(getBean(Saml2LogoutResponseResolver.class).resolve(any(), any())).willReturn(logoutResponse);
		this.mvc.perform(post("/logout/saml2/slo").param("SAMLRequest", "samlRequest").with(authentication(this.user)))
				.andReturn();
		verify(getBean(Saml2LogoutRequestValidator.class)).validate(any());
		verify(getBean(Saml2LogoutResponseResolver.class)).resolve(any(), any());
	}

	@Test
	public void saml2LogoutResponseWhenDefaultsThenRedirects() throws Exception {
		this.spring.register(Saml2LogoutDefaultsConfig.class).autowire();
		RelyingPartyRegistration registration = this.repository.findByRegistrationId("get");
		Saml2LogoutRequest logoutRequest = Saml2LogoutRequest.withRelyingPartyRegistration(registration)
				.samlRequest(this.rpLogoutRequest).id(this.rpLogoutRequestId).relayState(this.rpLogoutRequestRelayState)
				.parameters((params) -> params.put("Signature", this.rpLogoutRequestSignature)).build();
		this.logoutRequestRepository.saveLogoutRequest(logoutRequest, this.request, this.response);
		this.request.setParameter("RelayState", logoutRequest.getRelayState());
		assertThat(this.logoutRequestRepository.loadLogoutRequest(this.request)).isNotNull();
		this.mvc.perform(get("/logout/saml2/slo").session(((MockHttpSession) this.request.getSession()))
				.param("SAMLResponse", this.apLogoutResponse).param("RelayState", this.apLogoutResponseRelayState)
				.param("SigAlg", this.apLogoutResponseSigAlg).param("Signature", this.apLogoutResponseSignature)
				.with(samlQueryString())).andExpect(status().isFound()).andExpect(redirectedUrl("/login?logout"));
		verifyNoInteractions(getBean(LogoutHandler.class));
		assertThat(this.logoutRequestRepository.loadLogoutRequest(this.request)).isNull();
	}

	@Test
	public void saml2LogoutResponseWhenInvalidSamlResponseThen401() throws Exception {
		this.spring.register(Saml2LogoutDefaultsConfig.class).autowire();
		RelyingPartyRegistration registration = this.repository.findByRegistrationId("registration-id");
		Saml2LogoutRequest logoutRequest = Saml2LogoutRequest.withRelyingPartyRegistration(registration)
				.samlRequest(this.rpLogoutRequest).id(this.rpLogoutRequestId).relayState(this.rpLogoutRequestRelayState)
				.parameters((params) -> params.put("Signature", this.rpLogoutRequestSignature)).build();
		this.logoutRequestRepository.saveLogoutRequest(logoutRequest, this.request, this.response);
		String deflatedApLogoutResponse = Saml2Utils.samlEncode(
				Saml2Utils.samlInflate(Saml2Utils.samlDecode(this.apLogoutResponse)).getBytes(StandardCharsets.UTF_8));
		this.mvc.perform(post("/logout/saml2/slo").session((MockHttpSession) this.request.getSession())
				.param("SAMLResponse", deflatedApLogoutResponse).param("RelayState", this.rpLogoutRequestRelayState)
				.param("SigAlg", this.apLogoutRequestSigAlg).param("Signature", this.apLogoutResponseSignature)
				.with(samlQueryString())).andExpect(status().reason(containsString("invalid_signature")))
				.andExpect(status().isUnauthorized());
		verifyNoInteractions(getBean(LogoutHandler.class));
	}

	@Test
	public void saml2LogoutResponseWhenCustomLogoutResponseHandlerThenUses() throws Exception {
		this.spring.register(Saml2LogoutComponentsConfig.class).autowire();
		RelyingPartyRegistration registration = this.repository.findByRegistrationId("get");
		Saml2LogoutRequest logoutRequest = Saml2LogoutRequest.withRelyingPartyRegistration(registration)
				.samlRequest(this.rpLogoutRequest).id(this.rpLogoutRequestId).relayState(this.rpLogoutRequestRelayState)
				.parameters((params) -> params.put("Signature", this.rpLogoutRequestSignature)).build();
		given(getBean(Saml2LogoutRequestRepository.class).removeLogoutRequest(any(), any())).willReturn(logoutRequest);
		given(getBean(Saml2LogoutResponseValidator.class).validate(any()))
				.willReturn(Saml2LogoutValidatorResult.success());
		this.mvc.perform(get("/logout/saml2/slo").param("SAMLResponse", "samlResponse")).andReturn();
		verify(getBean(Saml2LogoutResponseValidator.class)).validate(any());
	}

	@Test
	public void saml2LogoutWhenCustomLogoutRequestRepositoryThenUses() throws Exception {
		this.spring.register(Saml2LogoutComponentsConfig.class).autowire();
		RelyingPartyRegistration registration = this.repository.findByRegistrationId("registration-id");
		Saml2LogoutRequest logoutRequest = Saml2LogoutRequest.withRelyingPartyRegistration(registration)
				.samlRequest(this.rpLogoutRequest).id(this.rpLogoutRequestId).relayState(this.rpLogoutRequestRelayState)
				.parameters((params) -> params.put("Signature", this.rpLogoutRequestSignature)).build();
		given(getBean(Saml2LogoutRequestResolver.class).resolve(any(), any())).willReturn(logoutRequest);
		this.mvc.perform(post("/logout").with(authentication(this.user)).with(csrf()));
		verify(getBean(Saml2LogoutRequestRepository.class)).saveLogoutRequest(eq(logoutRequest), any(), any());
	}

	@Test
	public void saml2LogoutWhenLogoutGetThenLogsOutAndSendsLogoutRequest() throws Exception {
		this.spring.register(Saml2LogoutWithHttpGet.class).autowire();
		MvcResult result = this.mvc.perform(get("/logout").with(authentication(this.user)))
				.andExpect(status().isFound()).andReturn();
		String location = result.getResponse().getHeader("Location");
		LogoutHandler logoutHandler = this.spring.getContext().getBean(LogoutHandler.class);
		assertThat(location).startsWith("https://ap.example.org/logout/saml2/request");
		verify(logoutHandler).logout(any(), any(), any());
	}

	@Test
	public void saml2LogoutWhenSaml2LogoutRequestFilterPostProcessedThenUses() {

		Saml2DefaultsWithObjectPostProcessorConfig.objectPostProcessor = spy(ReflectingObjectPostProcessor.class);
		this.spring.register(Saml2DefaultsWithObjectPostProcessorConfig.class).autowire();
		verify(Saml2DefaultsWithObjectPostProcessorConfig.objectPostProcessor)
				.postProcess(any(Saml2LogoutRequestFilter.class));

	}

	@Test
	public void saml2LogoutWhenSaml2LogoutResponseFilterPostProcessedThenUses() {

		Saml2DefaultsWithObjectPostProcessorConfig.objectPostProcessor = spy(ReflectingObjectPostProcessor.class);
		this.spring.register(Saml2DefaultsWithObjectPostProcessorConfig.class).autowire();
		verify(Saml2DefaultsWithObjectPostProcessorConfig.objectPostProcessor)
				.postProcess(any(Saml2LogoutResponseFilter.class));

	}

	@Test
	public void saml2LogoutWhenLogoutFilterPostProcessedThenUses() {

		Saml2DefaultsWithObjectPostProcessorConfig.objectPostProcessor = spy(ReflectingObjectPostProcessor.class);
		this.spring.register(Saml2DefaultsWithObjectPostProcessorConfig.class).autowire();
		verify(Saml2DefaultsWithObjectPostProcessorConfig.objectPostProcessor, atLeastOnce())
				.postProcess(any(LogoutFilter.class));

	}

	private <T> T getBean(Class<T> clazz) {
		return this.spring.getContext().getBean(clazz);
	}

	private SamlQueryStringRequestPostProcessor samlQueryString() {
		return new SamlQueryStringRequestPostProcessor();
	}

	@Configuration
	@EnableWebSecurity
	@Import(Saml2LoginConfigBeans.class)
	static class Saml2LogoutDefaultsConfig {

		LogoutHandler mockLogoutHandler = mock(LogoutHandler.class);

		@Bean
		SecurityFilterChain web(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests((authorize) -> authorize.anyRequest().authenticated())
				.logout((logout) -> logout.addLogoutHandler(this.mockLogoutHandler))
				.saml2Login(withDefaults())
				.saml2Logout(withDefaults());
			return http.build();
			// @formatter:on
		}

		@Bean
		LogoutHandler logoutHandler() {
			return this.mockLogoutHandler;
		}

	}

	@Configuration
	@EnableWebSecurity
	@Import(Saml2LoginConfigBeans.class)
	static class Saml2LogoutCsrfDisabledConfig {

		LogoutSuccessHandler mockLogoutSuccessHandler = mock(LogoutSuccessHandler.class);

		@Bean
		SecurityFilterChain web(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests((authorize) -> authorize.anyRequest().authenticated())
				.logout((logout) -> logout.logoutSuccessHandler(this.mockLogoutSuccessHandler))
				.saml2Login(withDefaults())
				.saml2Logout(withDefaults())
				.csrf().disable();
			return http.build();
			// @formatter:on
		}

		@Bean
		LogoutSuccessHandler logoutSuccessHandler() {
			return this.mockLogoutSuccessHandler;
		}

	}

	@Configuration
	@EnableWebSecurity
	@Import(Saml2LoginConfigBeans.class)
	static class Saml2LogoutWithHttpGet {

		LogoutHandler mockLogoutHandler = mock(LogoutHandler.class);

		@Bean
		SecurityFilterChain web(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests((authorize) -> authorize.anyRequest().authenticated())
				.logout((logout) -> logout.addLogoutHandler(this.mockLogoutHandler))
				.saml2Login(withDefaults())
				.saml2Logout((saml2) -> saml2.addObjectPostProcessor(new ObjectPostProcessor<LogoutFilter>() {
					@Override
					public <O extends LogoutFilter> O postProcess(O filter) {
						filter.setLogoutRequestMatcher(new AntPathRequestMatcher("/logout", "GET"));
						return filter;
					}
				}));
			return http.build();
			// @formatter:on
		}

		@Bean
		LogoutHandler logoutHandler() {
			return this.mockLogoutHandler;
		}

	}

	@Configuration
	@EnableWebSecurity
	@Import(Saml2LoginConfigBeans.class)
	static class Saml2DefaultsWithObjectPostProcessorConfig {

		static ObjectPostProcessor<Object> objectPostProcessor;

		@Bean
		SecurityFilterChain web(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests((authorize) -> authorize.anyRequest().authenticated())
				.saml2Login(withDefaults())
				.saml2Logout(withDefaults());
			return http.build();
			// @formatter:on
		}

		@Bean
		static ObjectPostProcessor<Object> objectPostProcessor() {
			return objectPostProcessor;
		}

	}

	@Configuration
	@EnableWebSecurity
	@Import(Saml2LoginConfigBeans.class)
	static class Saml2LogoutComponentsConfig {

		Saml2LogoutRequestRepository logoutRequestRepository = mock(Saml2LogoutRequestRepository.class);

		Saml2LogoutRequestValidator logoutRequestValidator = mock(Saml2LogoutRequestValidator.class);

		Saml2LogoutRequestResolver logoutRequestResolver = mock(Saml2LogoutRequestResolver.class);

		Saml2LogoutResponseValidator logoutResponseValidator = mock(Saml2LogoutResponseValidator.class);

		Saml2LogoutResponseResolver logoutResponseResolver = mock(Saml2LogoutResponseResolver.class);

		@Bean
		SecurityFilterChain web(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests((authorize) -> authorize.anyRequest().authenticated())
				.saml2Login(withDefaults())
				.saml2Logout((logout) -> logout
					.logoutRequest((request) -> request
						.logoutRequestRepository(this.logoutRequestRepository)
						.logoutRequestValidator(this.logoutRequestValidator)
						.logoutRequestResolver(this.logoutRequestResolver)
					)
					.logoutResponse((response) -> response
						.logoutResponseValidator(this.logoutResponseValidator)
						.logoutResponseResolver(this.logoutResponseResolver)
					)
				);
			return http.build();
			// @formatter:on
		}

		@Bean
		Saml2LogoutRequestRepository logoutRequestRepository() {
			return this.logoutRequestRepository;
		}

		@Bean
		Saml2LogoutRequestValidator logoutRequestAuthenticator() {
			return this.logoutRequestValidator;
		}

		@Bean
		Saml2LogoutRequestResolver logoutRequestResolver() {
			return this.logoutRequestResolver;
		}

		@Bean
		Saml2LogoutResponseValidator logoutResponseAuthenticator() {
			return this.logoutResponseValidator;
		}

		@Bean
		Saml2LogoutResponseResolver logoutResponseResolver() {
			return this.logoutResponseResolver;
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
			RelyingPartyRegistration post = withCreds.build();
			RelyingPartyRegistration get = withCreds.registrationId("get")
					.singleLogoutServiceBinding(Saml2MessageBinding.REDIRECT).build();
			RelyingPartyRegistration ap = withCreds.registrationId("ap").entityId("ap-entity-id")
					.assertingPartyDetails((party) -> party
							.singleLogoutServiceLocation("https://rp.example.org/logout/saml2/request")
							.singleLogoutServiceResponseLocation("https://rp.example.org/logout/saml2/response"))
					.build();

			return new InMemoryRelyingPartyRegistrationRepository(ap, get, post);
		}

		private Consumer<Collection<Saml2X509Credential>> credential(Saml2X509Credential credential) {
			return (credentials) -> credentials.add(credential);
		}

	}

	static class ReflectingObjectPostProcessor implements ObjectPostProcessor<Object> {

		@Override
		public <O> O postProcess(O object) {
			return object;
		}

	}

	static class SamlQueryStringRequestPostProcessor implements RequestPostProcessor {

		private Function<String, String> urlEncodingPostProcessor = Function.identity();

		SamlQueryStringRequestPostProcessor() {
			this(false);
		}

		SamlQueryStringRequestPostProcessor(boolean lowercased) {
			if (lowercased) {
				Pattern encoding = Pattern.compile("%\\d[A-Fa-f]");
				this.urlEncodingPostProcessor = (encoded) -> {
					Matcher m = encoding.matcher(encoded);
					while (m.find()) {
						String found = m.group(0);
						encoded = encoded.replace(found, found.toLowerCase());
					}
					return encoded;
				};
			}
		}

		@Override
		public MockHttpServletRequest postProcessRequest(MockHttpServletRequest request) {
			UriComponentsBuilder builder = UriComponentsBuilder.newInstance();
			for (Map.Entry<String, String[]> entries : request.getParameterMap().entrySet()) {
				builder.queryParam(entries.getKey(),
						UriUtils.encode(entries.getValue()[0], StandardCharsets.ISO_8859_1));
			}
			String queryString = this.urlEncodingPostProcessor.apply(builder.build(true).toUriString().substring(1));
			request.setQueryString(queryString);
			return request;
		}

	}

}
