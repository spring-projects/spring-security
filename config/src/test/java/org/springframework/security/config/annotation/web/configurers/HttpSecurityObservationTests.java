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

package org.springframework.security.config.annotation.web.configurers;

import java.util.Iterator;

import io.micrometer.observation.Observation;
import io.micrometer.observation.ObservationHandler;
import io.micrometer.observation.ObservationRegistry;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.test.SpringTestContext;
import org.springframework.security.config.test.SpringTestContextExtension;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.test.web.servlet.MockMvc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.springframework.security.config.Customizer.withDefaults;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * @author Josh Cummings
 *
 */
@ExtendWith(SpringTestContextExtension.class)
public class HttpSecurityObservationTests {

	@Autowired
	MockMvc mvc;

	public final SpringTestContext spring = new SpringTestContext(this);

	@Test
	public void getWhenUsingObservationRegistryThenObservesRequest() throws Exception {
		this.spring.register(ObservationRegistryConfig.class).autowire();
		// @formatter:off
		this.mvc.perform(get("/").with(httpBasic("user", "password")))
				.andExpect(status().isNotFound());
		// @formatter:on
		ObservationHandler<Observation.Context> handler = this.spring.getContext().getBean(ObservationHandler.class);
		ArgumentCaptor<Observation.Context> captor = ArgumentCaptor.forClass(Observation.Context.class);
		verify(handler, times(5)).onStart(captor.capture());
		Iterator<Observation.Context> contexts = captor.getAllValues().iterator();
		assertThat(contexts.next().getContextualName()).isEqualTo("security filterchain before");
		assertThat(contexts.next().getName()).isEqualTo("spring.security.authentications");
		assertThat(contexts.next().getName()).isEqualTo("spring.security.authorizations");
		assertThat(contexts.next().getName()).isEqualTo("spring.security.http.secured.requests");
		assertThat(contexts.next().getContextualName()).isEqualTo("security filterchain after");
	}

	@EnableWebSecurity
	@Configuration
	static class ObservationRegistryConfig {

		private ObservationHandler<Observation.Context> handler = mock(ObservationHandler.class);

		@Bean
		SecurityFilterChain app(HttpSecurity http) throws Exception {
			http.httpBasic(withDefaults()).authorizeHttpRequests((requests) -> requests.anyRequest().authenticated());
			return http.build();
		}

		@Bean
		UserDetailsService userDetailsService() {
			return new InMemoryUserDetailsManager(
					User.withDefaultPasswordEncoder().username("user").password("password").authorities("app").build());
		}

		@Bean
		ObservationHandler<Observation.Context> observationHandler() {
			return this.handler;
		}

		@Bean
		ObservationRegistry observationRegistry() {
			given(this.handler.supportsContext(any())).willReturn(true);
			ObservationRegistry registry = ObservationRegistry.create();
			registry.observationConfig().observationHandler(this.handler);
			return registry;
		}

	}

}
