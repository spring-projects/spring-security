/*
 * Copyright 2002-2023 the original author or authors.
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

import com.google.common.net.HttpHeaders;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.test.SpringTestContext;
import org.springframework.security.config.test.SpringTestContextExtension;
import org.springframework.security.saml2.provider.service.metadata.OpenSaml4MetadataResolver;
import org.springframework.security.saml2.provider.service.metadata.RequestMatcherMetadataResponseResolver;
import org.springframework.security.saml2.provider.service.metadata.Saml2MetadataResponse;
import org.springframework.security.saml2.provider.service.metadata.Saml2MetadataResponseResolver;
import org.springframework.security.saml2.provider.service.registration.InMemoryRelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.TestRelyingPartyRegistrations;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.test.web.servlet.MockMvc;

import static org.hamcrest.Matchers.containsString;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Tests for {@link Saml2MetadataConfigurer}
 */
@ExtendWith(SpringTestContextExtension.class)
public class Saml2MetadataConfigurerTests {

	static RelyingPartyRegistration registration = TestRelyingPartyRegistrations.relyingPartyRegistration().build();

	public final SpringTestContext spring = new SpringTestContext(this);

	@Autowired(required = false)
	MockMvc mvc;

	@Test
	void saml2MetadataRegistrationIdWhenDefaultsThenReturnsMetadata() throws Exception {
		this.spring.register(DefaultConfig.class).autowire();
		String filename = "saml-" + registration.getRegistrationId() + "-metadata.xml";
		this.mvc.perform(get("/saml2/metadata/" + registration.getRegistrationId()))
			.andExpect(status().isOk())
			.andExpect(header().string(HttpHeaders.CONTENT_DISPOSITION, containsString(filename)))
			.andExpect(content().string(containsString("md:EntityDescriptor")));
	}

	@Test
	void saml2MetadataRegistrationIdWhenWrongIdThenUnauthorized() throws Exception {
		this.spring.register(DefaultConfig.class).autowire();
		this.mvc.perform(get("/saml2/metadata/" + registration.getRegistrationId() + "wrong"))
			.andExpect(status().isUnauthorized());
	}

	@Test
	void saml2MetadataWhenDefaultsThenReturnsMetadata() throws Exception {
		this.spring.register(DefaultConfig.class).autowire();
		this.mvc.perform(get("/saml2/metadata"))
			.andExpect(status().isOk())
			.andExpect(header().string(HttpHeaders.CONTENT_DISPOSITION, containsString("-metadata.xml")))
			.andExpect(content().string(containsString("md:EntityDescriptor")));
	}

	@Test
	void saml2MetadataWhenMetadataResponseResolverThenUses() throws Exception {
		this.spring.register(DefaultConfig.class, MetadataResponseResolverConfig.class).autowire();
		Saml2MetadataResponseResolver metadataResponseResolver = this.spring.getContext()
			.getBean(Saml2MetadataResponseResolver.class);
		given(metadataResponseResolver.resolve(any(HttpServletRequest.class)))
			.willReturn(new Saml2MetadataResponse("metadata", "filename"));
		this.mvc.perform(get("/saml2/metadata"))
			.andExpect(status().isOk())
			.andExpect(header().string(HttpHeaders.CONTENT_DISPOSITION, containsString("filename")))
			.andExpect(content().string(containsString("metadata")));
		verify(metadataResponseResolver).resolve(any(HttpServletRequest.class));
	}

	@Test
	void saml2MetadataWhenMetadataResponseResolverDslThenUses() throws Exception {
		this.spring.register(MetadataResponseResolverDslConfig.class).autowire();
		this.mvc.perform(get("/saml2/metadata"))
			.andExpect(status().isOk())
			.andExpect(header().string(HttpHeaders.CONTENT_DISPOSITION, containsString("filename")))
			.andExpect(content().string(containsString("metadata")));
	}

	@Test
	void saml2MetadataWhenMetadataUrlThenUses() throws Exception {
		this.spring.register(MetadataUrlConfig.class).autowire();
		String filename = "saml-" + registration.getRegistrationId() + "-metadata.xml";
		this.mvc.perform(get("/saml/metadata"))
			.andExpect(status().isOk())
			.andExpect(header().string(HttpHeaders.CONTENT_DISPOSITION, containsString(filename)))
			.andExpect(content().string(containsString("md:EntityDescriptor")));
		this.mvc.perform(get("/saml2/metadata")).andExpect(status().isForbidden());
	}

	@EnableWebSecurity
	@Configuration
	@Import(RelyingPartyRegistrationConfig.class)
	static class DefaultConfig {

		@Bean
		SecurityFilterChain filters(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeHttpRequests((authorize) -> authorize.anyRequest().authenticated())
				.saml2Metadata(Customizer.withDefaults());
			return http.build();
			// @formatter:on
		}

	}

	@EnableWebSecurity
	@Configuration
	@Import(RelyingPartyRegistrationConfig.class)
	static class MetadataUrlConfig {

		@Bean
		SecurityFilterChain filters(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeHttpRequests((authorize) -> authorize.anyRequest().authenticated())
				.saml2Metadata((saml2) -> saml2.metadataUrl("/saml/metadata"));
			return http.build();
			// @formatter:on
		}

		// should ignore
		@Bean
		Saml2MetadataResponseResolver metadataResponseResolver(RelyingPartyRegistrationRepository registrations) {
			return new RequestMatcherMetadataResponseResolver(registrations, new OpenSaml4MetadataResolver());
		}

	}

	@EnableWebSecurity
	@Configuration
	@Import(RelyingPartyRegistrationConfig.class)
	static class MetadataResponseResolverDslConfig {

		Saml2MetadataResponseResolver metadataResponseResolver = mock(Saml2MetadataResponseResolver.class);

		{
			given(this.metadataResponseResolver.resolve(any(HttpServletRequest.class)))
				.willReturn(new Saml2MetadataResponse("metadata", "filename"));
		}

		@Bean
		SecurityFilterChain filters(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeHttpRequests((authorize) -> authorize.anyRequest().authenticated())
				.saml2Metadata((saml2) -> saml2.metadataResponseResolver(this.metadataResponseResolver));
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	static class MetadataResponseResolverConfig {

		Saml2MetadataResponseResolver metadataResponseResolver = mock(Saml2MetadataResponseResolver.class);

		@Bean
		Saml2MetadataResponseResolver metadataResponseResolver() {
			return this.metadataResponseResolver;
		}

	}

	@Configuration
	static class RelyingPartyRegistrationConfig {

		RelyingPartyRegistrationRepository registrations = new InMemoryRelyingPartyRegistrationRepository(registration);

		@Bean
		RelyingPartyRegistrationRepository registrations() {
			return this.registrations;
		}

	}

}
