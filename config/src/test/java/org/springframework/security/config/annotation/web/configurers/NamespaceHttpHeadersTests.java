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
package org.springframework.security.config.annotation.web.configurers;

import java.net.URI;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

import org.junit.Rule;
import org.junit.Test;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.test.SpringTestRule;
import org.springframework.security.web.header.writers.StaticHeadersWriter;
import org.springframework.security.web.header.writers.frameoptions.StaticAllowFromStrategy;
import org.springframework.security.web.header.writers.frameoptions.XFrameOptionsHeaderWriter;
import org.springframework.security.web.util.matcher.AnyRequestMatcher;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultMatcher;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;

/**
 * Tests to verify that all the functionality of <headers> attributes is present
 *
 * @author Rob Winch
 * @author Josh Cummings
 *
 */
public class NamespaceHttpHeadersTests {

	static final Map<String, String> defaultHeaders = new LinkedHashMap<>();

	static {
		defaultHeaders.put("X-Content-Type-Options", "nosniff");
		defaultHeaders.put("X-Frame-Options", "DENY");
		defaultHeaders.put("Strict-Transport-Security", "max-age=31536000 ; includeSubDomains");
		defaultHeaders.put("Cache-Control", "no-cache, no-store, max-age=0, must-revalidate");
		defaultHeaders.put("Expires", "0");
		defaultHeaders.put("Pragma", "no-cache");
		defaultHeaders.put("X-XSS-Protection", "1; mode=block");
	}

	@Rule
	public final SpringTestRule spring = new SpringTestRule();

	@Autowired
	MockMvc mvc;

	@Test
	public void secureRequestWhenDefaultConfigThenBehaviorMatchesNamespace() throws Exception {
		this.spring.register(HeadersDefaultConfig.class).autowire();

		this.mvc.perform(get("/").secure(true)).andExpect(includesDefaults());
	}

	@EnableWebSecurity
	static class HeadersDefaultConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.headers();
			// @formatter:on
		}

	}

	@Test
	public void secureRequestWhenCacheControlOnlyThenBehaviorMatchesNamespace() throws Exception {
		this.spring.register(HeadersCacheControlConfig.class).autowire();

		this.mvc.perform(get("/").secure(true)).andExpect(includes("Cache-Control", "Expires", "Pragma"));
	}

	@EnableWebSecurity
	static class HeadersCacheControlConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.headers()
					.defaultsDisabled()
					.cacheControl();
			// @formatter:on
		}

	}

	@Test
	public void secureRequestWhenHstsOnlyThenBehaviorMatchesNamespace() throws Exception {
		this.spring.register(HstsConfig.class).autowire();

		this.mvc.perform(get("/").secure(true)).andExpect(includes("Strict-Transport-Security"));
	}

	@EnableWebSecurity
	static class HstsConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.headers()
					.defaultsDisabled()
					.httpStrictTransportSecurity();
			// @formatter:on
		}

	}

	@Test
	public void requestWhenHstsCustomThenBehaviorMatchesNamespace() throws Exception {
		this.spring.register(HstsCustomConfig.class).autowire();

		this.mvc.perform(get("/"))
				.andExpect(includes(Collections.singletonMap("Strict-Transport-Security", "max-age=15768000")));
	}

	@EnableWebSecurity
	static class HstsCustomConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.headers()
					// hsts@request-matcher-ref, hsts@max-age-seconds, hsts@include-subdomains
					.defaultsDisabled()
					.httpStrictTransportSecurity()
						.requestMatcher(AnyRequestMatcher.INSTANCE)
						.maxAgeInSeconds(15768000)
						.includeSubDomains(false);
			// @formatter:on
		}

	}

	@Test
	public void requestWhenFrameOptionsSameOriginThenBehaviorMatchesNamespace() throws Exception {
		this.spring.register(FrameOptionsSameOriginConfig.class).autowire();

		this.mvc.perform(get("/")).andExpect(includes(Collections.singletonMap("X-Frame-Options", "SAMEORIGIN")));
	}

	@EnableWebSecurity
	static class FrameOptionsSameOriginConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.headers()
					// frame-options@policy=SAMEORIGIN
					.defaultsDisabled()
					.frameOptions()
						.sameOrigin();
			// @formatter:on
		}

	}

	// frame-options@strategy, frame-options@value, frame-options@parameter are not
	// provided instead use frame-options@ref

	@Test
	public void requestWhenFrameOptionsAllowFromThenBehaviorMatchesNamespace() throws Exception {
		this.spring.register(FrameOptionsAllowFromConfig.class).autowire();

		this.mvc.perform(get("/"))
				.andExpect(includes(Collections.singletonMap("X-Frame-Options", "ALLOW-FROM https://example.com")));
	}

	@EnableWebSecurity
	static class FrameOptionsAllowFromConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.headers()
					// frame-options@ref
					.defaultsDisabled()
					.addHeaderWriter(new XFrameOptionsHeaderWriter(
							new StaticAllowFromStrategy(URI.create("https://example.com"))));
			// @formatter:on
		}

	}

	@Test
	public void requestWhenXssOnlyThenBehaviorMatchesNamespace() throws Exception {
		this.spring.register(XssProtectionConfig.class).autowire();

		this.mvc.perform(get("/")).andExpect(includes("X-XSS-Protection"));
	}

	@EnableWebSecurity
	static class XssProtectionConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.headers()
					// xss-protection
					.defaultsDisabled()
					.xssProtection();
			// @formatter:on
		}

	}

	@Test
	public void requestWhenXssCustomThenBehaviorMatchesNamespace() throws Exception {
		this.spring.register(XssProtectionCustomConfig.class).autowire();

		this.mvc.perform(get("/")).andExpect(includes(Collections.singletonMap("X-XSS-Protection", "1")));
	}

	@EnableWebSecurity
	static class XssProtectionCustomConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.headers()
					// xss-protection@enabled and xss-protection@block
					.defaultsDisabled()
					.xssProtection()
						.xssProtectionEnabled(true)
						.block(false);
			// @formatter:on
		}

	}

	@Test
	public void requestWhenXContentTypeOptionsOnlyThenBehaviorMatchesNamespace() throws Exception {
		this.spring.register(ContentTypeOptionsConfig.class).autowire();

		this.mvc.perform(get("/")).andExpect(includes("X-Content-Type-Options"));
	}

	@EnableWebSecurity
	static class ContentTypeOptionsConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.headers()
					// content-type-options
					.defaultsDisabled()
					.contentTypeOptions();
			// @formatter:on
		}

	}

	// header@name / header@value are not provided instead use header@ref

	@Test
	public void requestWhenCustomHeaderOnlyThenBehaviorMatchesNamespace() throws Exception {
		this.spring.register(HeaderRefConfig.class).autowire();

		this.mvc.perform(get("/"))
				.andExpect(includes(Collections.singletonMap("customHeaderName", "customHeaderValue")));
	}

	@EnableWebSecurity
	static class HeaderRefConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.headers()
					.defaultsDisabled()
					.addHeaderWriter(new StaticHeadersWriter("customHeaderName", "customHeaderValue"));
			// @formatter:on
		}

	}

	private static ResultMatcher includesDefaults() {
		return includes(defaultHeaders);
	}

	private static ResultMatcher includes(String... headerNames) {
		return includes(defaultHeaders, headerNames);
	}

	private static ResultMatcher includes(Map<String, String> headers) {
		return includes(headers, headers.keySet().toArray(new String[headers.size()]));
	}

	private static ResultMatcher includes(Map<String, String> headers, String... headerNames) {
		return result -> {
			assertThat(result.getResponse().getHeaderNames()).hasSameSizeAs(headerNames);
			for (String headerName : headerNames) {
				header().string(headerName, headers.get(headerName)).match(result);
			}
		};
	}

}
