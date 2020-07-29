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
package org.springframework.security.config.http;

import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import com.google.common.collect.ImmutableMap;
import org.junit.Rule;
import org.junit.Test;

import org.springframework.beans.factory.BeanCreationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.parsing.BeanDefinitionParsingException;
import org.springframework.beans.factory.xml.XmlBeanDefinitionStoreException;
import org.springframework.security.config.test.SpringTestRule;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultMatcher;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * @author Rob Winch
 * @author Tim Ysewyn
 * @author Josh Cummings
 * @author Rafiullah Hamedy
 */
public class HttpHeadersConfigTests {

	private static final String CONFIG_LOCATION_PREFIX = "classpath:org/springframework/security/config/http/HttpHeadersConfigTests";

	static final Map<String, String> defaultHeaders = ImmutableMap.<String, String>builder()
			.put("X-Content-Type-Options", "nosniff").put("X-Frame-Options", "DENY")
			.put("Strict-Transport-Security", "max-age=31536000 ; includeSubDomains")
			.put("Cache-Control", "no-cache, no-store, max-age=0, must-revalidate").put("Expires", "0")
			.put("Pragma", "no-cache").put("X-XSS-Protection", "1; mode=block").build();

	@Rule
	public final SpringTestRule spring = new SpringTestRule();

	@Autowired
	MockMvc mvc;

	@Test
	public void requestWhenHeadersDisabledThenResponseExcludesAllSecureHeaders() throws Exception {

		this.spring.configLocations(this.xml("HeadersDisabled")).autowire();

		this.mvc.perform(get("/")).andExpect(status().isOk()).andExpect(excludesDefaults());
	}

	@Test
	public void requestWhenHeadersDisabledViaPlaceholderThenResponseExcludesAllSecureHeaders() throws Exception {

		System.setProperty("security.headers.disabled", "true");

		this.spring.configLocations(this.xml("DisabledWithPlaceholder")).autowire();

		this.mvc.perform(get("/").secure(true)).andExpect(status().isOk()).andExpect(excludesDefaults());
	}

	@Test
	public void requestWhenHeadersEnabledViaPlaceholderThenResponseIncludesAllSecureHeaders() throws Exception {

		System.setProperty("security.headers.disabled", "false");

		this.spring.configLocations(this.xml("DisabledWithPlaceholder")).autowire();

		this.mvc.perform(get("/").secure(true)).andExpect(status().isOk()).andExpect(includesDefaults());
	}

	@Test
	public void requestWhenHeadersDisabledRefMissingPlaceholderThenResponseIncludesAllSecureHeaders() throws Exception {

		System.clearProperty("security.headers.disabled");

		this.spring.configLocations(this.xml("DisabledWithPlaceholder")).autowire();

		this.mvc.perform(get("/").secure(true)).andExpect(status().isOk()).andExpect(includesDefaults());
	}

	@Test
	public void configureWhenHeadersDisabledHavingChildElementThenAutowireFails() {
		assertThatThrownBy(() -> this.spring.configLocations(this.xml("HeadersDisabledHavingChildElement")).autowire())
				.isInstanceOf(BeanDefinitionParsingException.class)
				.hasMessageContaining("Cannot specify <headers disabled=\"true\"> with child elements");
	}

	@Test
	public void requestWhenHeadersEnabledThenResponseContainsAllSecureHeaders() throws Exception {

		this.spring.configLocations(this.xml("DefaultConfig")).autowire();

		this.mvc.perform(get("/").secure(true)).andExpect(status().isOk()).andExpect(includesDefaults());
	}

	@Test
	public void requestWhenHeadersElementUsedThenResponseContainsAllSecureHeaders() throws Exception {

		this.spring.configLocations(this.xml("HeadersEnabled")).autowire();

		this.mvc.perform(get("/").secure(true)).andExpect(status().isOk()).andExpect(includesDefaults());
	}

	@Test
	public void requestWhenFrameOptionsConfiguredThenIncludesHeader() throws Exception {

		Map<String, String> headers = new HashMap(defaultHeaders);
		headers.put("X-Frame-Options", "SAMEORIGIN");

		this.spring.configLocations(this.xml("WithFrameOptions")).autowire();

		this.mvc.perform(get("/").secure(true)).andExpect(status().isOk()).andExpect(includes(headers));
	}

	/**
	 * gh-3986
	 */
	@Test
	public void requestWhenDefaultsDisabledWithNoOverrideThenExcludesAllSecureHeaders() throws Exception {

		this.spring.configLocations(this.xml("DefaultsDisabledWithNoOverride")).autowire();

		this.mvc.perform(get("/").secure(true)).andExpect(status().isOk()).andExpect(excludesDefaults());
	}

	@Test
	public void requestWhenDefaultsDisabledWithPlaceholderTrueThenExcludesAllSecureHeaders() throws Exception {

		System.setProperty("security.headers.defaults.disabled", "true");

		this.spring.configLocations(this.xml("DefaultsDisabledWithPlaceholder")).autowire();

		this.mvc.perform(get("/").secure(true)).andExpect(status().isOk()).andExpect(excludesDefaults());
	}

	@Test
	public void requestWhenDefaultsDisabledWithPlaceholderFalseThenIncludeAllSecureHeaders() throws Exception {

		System.setProperty("security.headers.defaults.disabled", "false");

		this.spring.configLocations(this.xml("DefaultsDisabledWithPlaceholder")).autowire();

		this.mvc.perform(get("/").secure(true)).andExpect(status().isOk()).andExpect(includesDefaults());
	}

	@Test
	public void requestWhenDefaultsDisabledWithPlaceholderMissingThenIncludeAllSecureHeaders() throws Exception {

		System.clearProperty("security.headers.defaults.disabled");

		this.spring.configLocations(this.xml("DefaultsDisabledWithPlaceholder")).autowire();

		this.mvc.perform(get("/").secure(true)).andExpect(status().isOk()).andExpect(includesDefaults());
	}

	@Test
	public void requestWhenUsingContentTypeOptionsThenDefaultsToNoSniff() throws Exception {

		Set<String> excludedHeaders = new HashSet<>(defaultHeaders.keySet());
		excludedHeaders.remove("X-Content-Type-Options");

		this.spring.configLocations(this.xml("DefaultsDisabledWithContentTypeOptions")).autowire();

		this.mvc.perform(get("/")).andExpect(status().isOk())
				.andExpect(header().string("X-Content-Type-Options", "nosniff")).andExpect(excludes(excludedHeaders));
	}

	@Test
	public void requestWhenUsingFrameOptionsThenDefaultsToDeny() throws Exception {

		Set<String> excludedHeaders = new HashSet<>(defaultHeaders.keySet());
		excludedHeaders.remove("X-Frame-Options");

		this.spring.configLocations(this.xml("DefaultsDisabledWithFrameOptions")).autowire();

		this.mvc.perform(get("/")).andExpect(status().isOk()).andExpect(header().string("X-Frame-Options", "DENY"))
				.andExpect(excludes(excludedHeaders));
	}

	@Test
	public void requestWhenUsingFrameOptionsDenyThenRespondsWithDeny() throws Exception {

		Set<String> excludedHeaders = new HashSet<>(defaultHeaders.keySet());
		excludedHeaders.remove("X-Frame-Options");

		this.spring.configLocations(this.xml("DefaultsDisabledWithFrameOptionsDeny")).autowire();

		this.mvc.perform(get("/")).andExpect(status().isOk()).andExpect(header().string("X-Frame-Options", "DENY"))
				.andExpect(excludes(excludedHeaders));
	}

	@Test
	public void requestWhenUsingFrameOptionsSameOriginThenRespondsWithSameOrigin() throws Exception {

		Set<String> excludedHeaders = new HashSet<>(defaultHeaders.keySet());
		excludedHeaders.remove("X-Frame-Options");

		this.spring.configLocations(this.xml("DefaultsDisabledWithFrameOptionsSameOrigin")).autowire();

		this.mvc.perform(get("/")).andExpect(status().isOk())
				.andExpect(header().string("X-Frame-Options", "SAMEORIGIN")).andExpect(excludes(excludedHeaders));
	}

	@Test
	public void configureWhenUsingFrameOptionsAllowFromNoOriginThenAutowireFails() {
		assertThatThrownBy(() -> this.spring
				.configLocations(this.xml("DefaultsDisabledWithFrameOptionsAllowFromNoOrigin")).autowire())
						.isInstanceOf(BeanDefinitionParsingException.class)
						.hasMessageContaining("Strategy requires a 'value' to be set."); // FIXME
																							// better
																							// error
																							// message?
	}

	@Test
	public void configureWhenUsingFrameOptionsAllowFromBlankOriginThenAutowireFails() {
		assertThatThrownBy(() -> this.spring
				.configLocations(this.xml("DefaultsDisabledWithFrameOptionsAllowFromBlankOrigin")).autowire())
						.isInstanceOf(BeanDefinitionParsingException.class)
						.hasMessageContaining("Strategy requires a 'value' to be set."); // FIXME
																							// better
																							// error
																							// message?
	}

	@Test
	public void requestWhenUsingFrameOptionsAllowFromThenRespondsWithAllowFrom() throws Exception {

		Set<String> excludedHeaders = new HashSet<>(defaultHeaders.keySet());
		excludedHeaders.remove("X-Frame-Options");

		this.spring.configLocations(this.xml("DefaultsDisabledWithFrameOptionsAllowFrom")).autowire();

		this.mvc.perform(get("/")).andExpect(status().isOk())
				.andExpect(header().string("X-Frame-Options", "ALLOW-FROM https://example.org"))
				.andExpect(excludes(excludedHeaders));
	}

	@Test
	public void requestWhenUsingFrameOptionsAllowFromWhitelistThenRespondsWithAllowFrom() throws Exception {

		Set<String> excludedHeaders = new HashSet<>(defaultHeaders.keySet());
		excludedHeaders.remove("X-Frame-Options");

		this.spring.configLocations(this.xml("DefaultsDisabledWithFrameOptionsAllowFromWhitelist")).autowire();

		this.mvc.perform(get("/").param("from", "https://example.org")).andExpect(status().isOk())
				.andExpect(header().string("X-Frame-Options", "ALLOW-FROM https://example.org"))
				.andExpect(excludes(excludedHeaders));

		this.mvc.perform(get("/")).andExpect(status().isOk()).andExpect(header().string("X-Frame-Options", "DENY"))
				.andExpect(excludes(excludedHeaders));
	}

	@Test
	public void requestWhenUsingCustomHeaderThenRespondsWithThatHeader() throws Exception {

		this.spring.configLocations(this.xml("DefaultsDisabledWithCustomHeader")).autowire();

		this.mvc.perform(get("/")).andExpect(status().isOk()).andExpect(header().string("a", "b"))
				.andExpect(header().string("c", "d")).andExpect(excludesDefaults());
	}

	@Test
	public void requestWhenUsingCustomHeaderWriterThenRespondsWithThatHeader() throws Exception {

		this.spring.configLocations(this.xml("DefaultsDisabledWithCustomHeaderWriter")).autowire();

		this.mvc.perform(get("/")).andExpect(status().isOk()).andExpect(header().string("abc", "def"))
				.andExpect(excludesDefaults());
	}

	@Test
	public void configureWhenUsingCustomHeaderNameOnlyThenAutowireFails() {
		assertThatThrownBy(() -> this.spring.configLocations(this.xml("DefaultsDisabledWithOnlyHeaderName")).autowire())
				.isInstanceOf(BeanCreationException.class);
	}

	@Test
	public void configureWhenUsingCustomHeaderValueOnlyThenAutowireFails() {
		assertThatThrownBy(
				() -> this.spring.configLocations(this.xml("DefaultsDisabledWithOnlyHeaderValue")).autowire())
						.isInstanceOf(BeanCreationException.class);
	}

	@Test
	public void requestWhenUsingXssProtectionThenDefaultsToModeBlock() throws Exception {

		Set<String> excludedHeaders = new HashSet<>(defaultHeaders.keySet());
		excludedHeaders.remove("X-XSS-Protection");

		this.spring.configLocations(this.xml("DefaultsDisabledWithXssProtection")).autowire();

		this.mvc.perform(get("/")).andExpect(status().isOk())
				.andExpect(header().string("X-XSS-Protection", "1; mode=block")).andExpect(excludes(excludedHeaders));
	}

	@Test
	public void requestWhenEnablingXssProtectionThenDefaultsToModeBlock() throws Exception {

		Set<String> excludedHeaders = new HashSet<>(defaultHeaders.keySet());
		excludedHeaders.remove("X-XSS-Protection");

		this.spring.configLocations(this.xml("DefaultsDisabledWithXssProtectionEnabled")).autowire();

		this.mvc.perform(get("/")).andExpect(status().isOk())
				.andExpect(header().string("X-XSS-Protection", "1; mode=block")).andExpect(excludes(excludedHeaders));
	}

	@Test
	public void requestWhenDisablingXssProtectionThenDefaultsToZero() throws Exception {

		Set<String> excludedHeaders = new HashSet<>(defaultHeaders.keySet());
		excludedHeaders.remove("X-XSS-Protection");

		this.spring.configLocations(this.xml("DefaultsDisabledWithXssProtectionDisabled")).autowire();

		this.mvc.perform(get("/")).andExpect(status().isOk()).andExpect(header().string("X-XSS-Protection", "0"))
				.andExpect(excludes(excludedHeaders));
	}

	@Test
	public void configureWhenXssProtectionDisabledAndBlockSetThenAutowireFails() {
		assertThatThrownBy(() -> this.spring
				.configLocations(this.xml("DefaultsDisabledWithXssProtectionDisabledAndBlockSet")).autowire())
						.isInstanceOf(BeanCreationException.class)
						.hasMessageContaining("Cannot set block to true with enabled false");
	}

	@Test
	public void requestWhenUsingCacheControlThenRespondsWithCorrespondingHeaders() throws Exception {

		Map<String, String> includedHeaders = ImmutableMap.<String, String>builder()
				.put("Cache-Control", "no-cache, no-store, max-age=0, must-revalidate").put("Expires", "0")
				.put("Pragma", "no-cache").build();

		this.spring.configLocations(this.xml("DefaultsDisabledWithCacheControl")).autowire();

		this.mvc.perform(get("/")).andExpect(status().isOk()).andExpect(includes(includedHeaders));
	}

	@Test
	public void requestWhenUsingHstsThenRespondsWithHstsHeader() throws Exception {

		Set<String> excludedHeaders = new HashSet<>(defaultHeaders.keySet());
		excludedHeaders.remove("Strict-Transport-Security");

		this.spring.configLocations(this.xml("DefaultsDisabledWithHsts")).autowire();

		this.mvc.perform(get("/").secure(true)).andExpect(status().isOk())
				.andExpect(header().string("Strict-Transport-Security", "max-age=31536000 ; includeSubDomains"))
				.andExpect(excludes(excludedHeaders));
	}

	@Test
	public void insecureRequestWhenUsingHstsThenExcludesHstsHeader() throws Exception {

		this.spring.configLocations(this.xml("DefaultsDisabledWithHsts")).autowire();

		this.mvc.perform(get("/")).andExpect(status().isOk()).andExpect(excludesDefaults());
	}

	@Test
	public void insecureRequestWhenUsingCustomHstsRequestMatcherThenIncludesHstsHeader() throws Exception {

		Set<String> excludedHeaders = new HashSet<>(defaultHeaders.keySet());
		excludedHeaders.remove("Strict-Transport-Security");

		this.spring.configLocations(this.xml("DefaultsDisabledWithCustomHstsRequestMatcher")).autowire();

		this.mvc.perform(get("/")).andExpect(status().isOk())
				.andExpect(header().string("Strict-Transport-Security", "max-age=1"))
				.andExpect(excludes(excludedHeaders));
	}

	@Test
	public void configureWhenUsingHpkpWithoutPinsThenAutowireFails() {
		assertThatThrownBy(() -> this.spring.configLocations(this.xml("DefaultsDisabledWithEmptyHpkp")).autowire())
				.isInstanceOf(XmlBeanDefinitionStoreException.class)
				.hasMessageContaining("The content of element 'hpkp' is not complete");
	}

	@Test
	public void configureWhenUsingHpkpWithEmptyPinsThenAutowireFails() {
		assertThatThrownBy(() -> this.spring.configLocations(this.xml("DefaultsDisabledWithEmptyPins")).autowire())
				.isInstanceOf(XmlBeanDefinitionStoreException.class)
				.hasMessageContaining("The content of element 'pins' is not complete");
	}

	@Test
	public void requestWhenUsingHpkpThenIncludesHpkpHeader() throws Exception {
		this.spring.configLocations(this.xml("DefaultsDisabledWithHpkp")).autowire();

		this.mvc.perform(get("/").secure(true)).andExpect(status().isOk())
				.andExpect(header().string("Public-Key-Pins-Report-Only",
						"max-age=5184000 ; pin-sha256=\"d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM=\""))
				.andExpect(excludesDefaults());
	}

	@Test
	public void requestWhenUsingHpkpDefaultsThenIncludesHpkpHeaderUsingSha256() throws Exception {
		this.spring.configLocations(this.xml("DefaultsDisabledWithHpkpDefaults")).autowire();

		this.mvc.perform(get("/").secure(true)).andExpect(status().isOk())
				.andExpect(header().string("Public-Key-Pins-Report-Only",
						"max-age=5184000 ; pin-sha256=\"d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM=\""))
				.andExpect(excludesDefaults());
	}

	@Test
	public void insecureRequestWhenUsingHpkpThenExcludesHpkpHeader() throws Exception {
		this.spring.configLocations(this.xml("DefaultsDisabledWithHpkpDefaults")).autowire();

		this.mvc.perform(get("/")).andExpect(status().isOk())
				.andExpect(header().doesNotExist("Public-Key-Pins-Report-Only")).andExpect(excludesDefaults());
	}

	@Test
	public void requestWhenUsingHpkpCustomMaxAgeThenIncludesHpkpHeaderAccordingly() throws Exception {
		this.spring.configLocations(this.xml("DefaultsDisabledWithHpkpMaxAge")).autowire();

		this.mvc.perform(get("/").secure(true)).andExpect(status().isOk())
				.andExpect(header().string("Public-Key-Pins-Report-Only",
						"max-age=604800 ; pin-sha256=\"d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM=\""))
				.andExpect(excludesDefaults());
	}

	@Test
	public void requestWhenUsingHpkpReportThenIncludesHpkpHeaderAccordingly() throws Exception {
		this.spring.configLocations(this.xml("DefaultsDisabledWithHpkpReport")).autowire();

		this.mvc.perform(get("/").secure(true)).andExpect(status().isOk())
				.andExpect(header().string("Public-Key-Pins",
						"max-age=5184000 ; pin-sha256=\"d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM=\""))
				.andExpect(excludesDefaults());
	}

	@Test
	public void requestWhenUsingHpkpIncludeSubdomainsThenIncludesHpkpHeaderAccordingly() throws Exception {
		this.spring.configLocations(this.xml("DefaultsDisabledWithHpkpIncludeSubdomains")).autowire();

		this.mvc.perform(get("/").secure(true)).andExpect(status().isOk()).andExpect(header().string(
				"Public-Key-Pins-Report-Only",
				"max-age=5184000 ; pin-sha256=\"d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM=\" ; includeSubDomains"))
				.andExpect(excludesDefaults());
	}

	@Test
	public void requestWhenUsingHpkpReportUriThenIncludesHpkpHeaderAccordingly() throws Exception {
		this.spring.configLocations(this.xml("DefaultsDisabledWithHpkpReportUri")).autowire();

		this.mvc.perform(get("/").secure(true)).andExpect(status().isOk()).andExpect(header().string(
				"Public-Key-Pins-Report-Only",
				"max-age=5184000 ; pin-sha256=\"d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM=\" ; report-uri=\"https://example.net/pkp-report\""))
				.andExpect(excludesDefaults());
	}

	@Test
	public void requestWhenCacheControlDisabledThenExcludesHeader() throws Exception {

		Collection<String> cacheControl = Arrays.asList("Cache-Control", "Expires", "Pragma");
		Map<String, String> allButCacheControl = remove(defaultHeaders, cacheControl);

		this.spring.configLocations(this.xml("CacheControlDisabled")).autowire();

		this.mvc.perform(get("/").secure(true)).andExpect(status().isOk()).andExpect(includes(allButCacheControl))
				.andExpect(excludes(cacheControl));
	}

	@Test
	public void requestWhenContentTypeOptionsDisabledThenExcludesHeader() throws Exception {

		Collection<String> contentTypeOptions = Arrays.asList("X-Content-Type-Options");
		Map<String, String> allButContentTypeOptions = remove(defaultHeaders, contentTypeOptions);

		this.spring.configLocations(this.xml("ContentTypeOptionsDisabled")).autowire();

		this.mvc.perform(get("/").secure(true)).andExpect(status().isOk()).andExpect(includes(allButContentTypeOptions))
				.andExpect(excludes(contentTypeOptions));
	}

	@Test
	public void requestWhenHstsDisabledThenExcludesHeader() throws Exception {

		Collection<String> hsts = Arrays.asList("Strict-Transport-Security");
		Map<String, String> allButHsts = remove(defaultHeaders, hsts);

		this.spring.configLocations(this.xml("HstsDisabled")).autowire();

		this.mvc.perform(get("/").secure(true)).andExpect(status().isOk()).andExpect(includes(allButHsts))
				.andExpect(excludes(hsts));
	}

	@Test
	public void requestWhenHpkpDisabledThenExcludesHeader() throws Exception {

		this.spring.configLocations(this.xml("HpkpDisabled")).autowire();

		this.mvc.perform(get("/").secure(true)).andExpect(status().isOk()).andExpect(includesDefaults());
	}

	@Test
	public void requestWhenFrameOptionsDisabledThenExcludesHeader() throws Exception {

		Collection<String> frameOptions = Arrays.asList("X-Frame-Options");
		Map<String, String> allButFrameOptions = remove(defaultHeaders, frameOptions);

		this.spring.configLocations(this.xml("FrameOptionsDisabled")).autowire();

		this.mvc.perform(get("/").secure(true)).andExpect(status().isOk()).andExpect(includes(allButFrameOptions))
				.andExpect(excludes(frameOptions));
	}

	@Test
	public void requestWhenXssProtectionDisabledThenExcludesHeader() throws Exception {

		Collection<String> xssProtection = Arrays.asList("X-XSS-Protection");
		Map<String, String> allButXssProtection = remove(defaultHeaders, xssProtection);

		this.spring.configLocations(this.xml("XssProtectionDisabled")).autowire();

		this.mvc.perform(get("/").secure(true)).andExpect(status().isOk()).andExpect(includes(allButXssProtection))
				.andExpect(excludes(xssProtection));
	}

	@Test
	public void configureWhenHstsDisabledAndIncludeSubdomainsSpecifiedThenAutowireFails() {
		assertThatThrownBy(
				() -> this.spring.configLocations(this.xml("HstsDisabledSpecifyingIncludeSubdomains")).autowire())
						.isInstanceOf(BeanDefinitionParsingException.class).hasMessageContaining("include-subdomains");
	}

	@Test
	public void configureWhenHstsDisabledAndMaxAgeSpecifiedThenAutowireFails() {
		assertThatThrownBy(() -> this.spring.configLocations(this.xml("HstsDisabledSpecifyingMaxAge")).autowire())
				.isInstanceOf(BeanDefinitionParsingException.class).hasMessageContaining("max-age");
	}

	@Test
	public void configureWhenHstsDisabledAndRequestMatcherSpecifiedThenAutowireFails() {
		assertThatThrownBy(
				() -> this.spring.configLocations(this.xml("HstsDisabledSpecifyingRequestMatcher")).autowire())
						.isInstanceOf(BeanDefinitionParsingException.class).hasMessageContaining("request-matcher-ref");
	}

	@Test
	public void configureWhenXssProtectionDisabledAndEnabledThenAutowireFails() {
		assertThatThrownBy(() -> this.spring.configLocations(this.xml("XssProtectionDisabledAndEnabled")).autowire())
				.isInstanceOf(BeanDefinitionParsingException.class).hasMessageContaining("enabled");
	}

	@Test
	public void configureWhenXssProtectionDisabledAndBlockSpecifiedThenAutowireFails() {
		assertThatThrownBy(
				() -> this.spring.configLocations(this.xml("XssProtectionDisabledSpecifyingBlock")).autowire())
						.isInstanceOf(BeanDefinitionParsingException.class).hasMessageContaining("block");
	}

	@Test
	public void configureWhenFrameOptionsDisabledAndPolicySpecifiedThenAutowireFails() {
		assertThatThrownBy(
				() -> this.spring.configLocations(this.xml("FrameOptionsDisabledSpecifyingPolicy")).autowire())
						.isInstanceOf(BeanDefinitionParsingException.class).hasMessageContaining("policy");
	}

	@Test
	public void requestWhenContentSecurityPolicyDirectivesConfiguredThenIncludesDirectives() throws Exception {

		Map<String, String> includedHeaders = new HashMap<>(defaultHeaders);
		includedHeaders.put("Content-Security-Policy", "default-src 'self'");

		this.spring.configLocations(this.xml("ContentSecurityPolicyWithPolicyDirectives")).autowire();

		this.mvc.perform(get("/").secure(true)).andExpect(status().isOk()).andExpect(includes(includedHeaders));
	}

	@Test
	public void requestWhenHeadersDisabledAndContentSecurityPolicyConfiguredThenExcludesHeader() throws Exception {

		this.spring.configLocations(this.xml("HeadersDisabledWithContentSecurityPolicy")).autowire();

		this.mvc.perform(get("/")).andExpect(status().isOk()).andExpect(excludesDefaults())
				.andExpect(excludes("Content-Security-Policy"));
	}

	@Test
	public void requestWhenDefaultsDisabledAndContentSecurityPolicyConfiguredThenIncludesHeader() throws Exception {

		this.spring.configLocations(this.xml("DefaultsDisabledWithContentSecurityPolicy")).autowire();

		this.mvc.perform(get("/")).andExpect(status().isOk()).andExpect(excludesDefaults())
				.andExpect(header().string("Content-Security-Policy", "default-src 'self'"));
	}

	@Test
	public void configureWhenContentSecurityPolicyConfiguredWithEmptyDirectivesThenAutowireFails() {
		assertThatThrownBy(
				() -> this.spring.configLocations(this.xml("ContentSecurityPolicyWithEmptyDirectives")).autowire())
						.isInstanceOf(BeanDefinitionParsingException.class);
	}

	@Test
	public void requestWhenContentSecurityPolicyConfiguredWithReportOnlyThenIncludesReportOnlyHeader()
			throws Exception {

		Map<String, String> includedHeaders = new HashMap<>(defaultHeaders);
		includedHeaders.put("Content-Security-Policy-Report-Only",
				"default-src https:; report-uri https://example.org/");

		this.spring.configLocations(this.xml("ContentSecurityPolicyWithReportOnly")).autowire();

		this.mvc.perform(get("/").secure(true)).andExpect(status().isOk()).andExpect(includes(includedHeaders));
	}

	@Test
	public void requestWhenReferrerPolicyConfiguredThenResponseDefaultsToNoReferrer() throws Exception {

		this.spring.configLocations(this.xml("DefaultsDisabledWithReferrerPolicy")).autowire();

		this.mvc.perform(get("/")).andExpect(status().isOk()).andExpect(excludesDefaults())
				.andExpect(header().string("Referrer-Policy", "no-referrer"));
	}

	@Test
	public void requestWhenReferrerPolicyConfiguredWithSameOriginThenRespondsWithSameOrigin() throws Exception {

		this.spring.configLocations(this.xml("DefaultsDisabledWithReferrerPolicySameOrigin")).autowire();

		this.mvc.perform(get("/")).andExpect(status().isOk()).andExpect(excludesDefaults())
				.andExpect(header().string("Referrer-Policy", "same-origin"));
	}

	private static ResultMatcher includesDefaults() {
		return includes(defaultHeaders);
	}

	private static ResultMatcher includes(Map<String, String> headers) {
		return result -> {
			for (Map.Entry<String, String> header : headers.entrySet()) {
				header().string(header.getKey(), header.getValue()).match(result);
			}
		};
	}

	private static ResultMatcher excludesDefaults() {
		return excludes(defaultHeaders.keySet());
	}

	private static ResultMatcher excludes(Collection<String> headers) {
		return result -> {
			for (String name : headers) {
				header().doesNotExist(name).match(result);
			}
		};
	}

	private static ResultMatcher excludes(String... headers) {
		return excludes(Arrays.asList(headers));
	}

	private static <K, V> Map<K, V> remove(Map<K, V> map, Collection<K> keys) {
		Map<K, V> copy = new HashMap<>(map);

		for (K key : keys) {
			copy.remove(key);
		}

		return copy;
	}

	private String xml(String configName) {
		return CONFIG_LOCATION_PREFIX + "-" + configName + ".xml";
	}

	@RestController
	public static class SimpleController {

		@GetMapping("/")
		public String ok() {
			return "ok";
		}

	}

}
