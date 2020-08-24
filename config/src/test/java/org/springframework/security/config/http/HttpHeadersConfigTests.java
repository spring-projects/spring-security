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

import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
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
	// @formatter:off
	static final Map<String, String> defaultHeaders = ImmutableMap.<String, String>builder()
			.put("X-Content-Type-Options", "nosniff").put("X-Frame-Options", "DENY")
			.put("Strict-Transport-Security", "max-age=31536000 ; includeSubDomains")
			.put("Cache-Control", "no-cache, no-store, max-age=0, must-revalidate")
			.put("Expires", "0")
			.put("Pragma", "no-cache")
			.put("X-XSS-Protection", "1; mode=block")
			.build();
	// @formatter:on

	@Rule
	public final SpringTestRule spring = new SpringTestRule();

	@Autowired
	MockMvc mvc;

	@Test
	public void requestWhenHeadersDisabledThenResponseExcludesAllSecureHeaders() throws Exception {
		this.spring.configLocations(this.xml("HeadersDisabled")).autowire();
		// @formatter:off
		this.mvc.perform(get("/"))
				.andExpect(status().isOk())
				.andExpect(excludesDefaults());
		// @formatter:on
	}

	@Test
	public void requestWhenHeadersDisabledViaPlaceholderThenResponseExcludesAllSecureHeaders() throws Exception {
		System.setProperty("security.headers.disabled", "true");
		this.spring.configLocations(this.xml("DisabledWithPlaceholder")).autowire();
		// @formatter:off
		this.mvc.perform(get("/").secure(true))
				.andExpect(status().isOk())
				.andExpect(excludesDefaults());
		// @formatter:on
	}

	@Test
	public void requestWhenHeadersEnabledViaPlaceholderThenResponseIncludesAllSecureHeaders() throws Exception {
		System.setProperty("security.headers.disabled", "false");
		this.spring.configLocations(this.xml("DisabledWithPlaceholder")).autowire();
		// @formatter:off
		this.mvc.perform(get("/").secure(true))
				.andExpect(status().isOk())
				.andExpect(includesDefaults());
		// @formatter:on
	}

	@Test
	public void requestWhenHeadersDisabledRefMissingPlaceholderThenResponseIncludesAllSecureHeaders() throws Exception {
		System.clearProperty("security.headers.disabled");
		this.spring.configLocations(this.xml("DisabledWithPlaceholder")).autowire();
		// @formatter:off
		this.mvc.perform(get("/").secure(true))
				.andExpect(status().isOk())
				.andExpect(includesDefaults());
		// @formatter:on
	}

	@Test
	public void configureWhenHeadersDisabledHavingChildElementThenAutowireFails() {
		assertThatExceptionOfType(BeanDefinitionParsingException.class)
				.isThrownBy(() -> this.spring.configLocations(this.xml("HeadersDisabledHavingChildElement")).autowire())
				.withMessageContaining("Cannot specify <headers disabled=\"true\"> with child elements");
	}

	@Test
	public void requestWhenHeadersEnabledThenResponseContainsAllSecureHeaders() throws Exception {
		this.spring.configLocations(this.xml("DefaultConfig")).autowire();
		// @formatter:off
		this.mvc.perform(get("/").secure(true))
				.andExpect(status().isOk())
				.andExpect(includesDefaults());
		// @formatter:on
	}

	@Test
	public void requestWhenHeadersElementUsedThenResponseContainsAllSecureHeaders() throws Exception {
		this.spring.configLocations(this.xml("HeadersEnabled")).autowire();
		// @formatter:off
		this.mvc.perform(get("/").secure(true))
				.andExpect(status().isOk())
				.andExpect(includesDefaults());
		// @formatter:on
	}

	@Test
	public void requestWhenFrameOptionsConfiguredThenIncludesHeader() throws Exception {
		Map<String, String> headers = new HashMap(defaultHeaders);
		headers.put("X-Frame-Options", "SAMEORIGIN");
		this.spring.configLocations(this.xml("WithFrameOptions")).autowire();
		// @formatter:off
		this.mvc.perform(get("/").secure(true))
				.andExpect(status().isOk())
				.andExpect(includes(headers));
		// @formatter:on
	}

	/**
	 * gh-3986
	 */
	@Test
	public void requestWhenDefaultsDisabledWithNoOverrideThenExcludesAllSecureHeaders() throws Exception {
		this.spring.configLocations(this.xml("DefaultsDisabledWithNoOverride")).autowire();
		// @formatter:off
		this.mvc.perform(get("/").secure(true))
				.andExpect(status().isOk())
				.andExpect(excludesDefaults());
		// @formatter:on
	}

	@Test
	public void requestWhenDefaultsDisabledWithPlaceholderTrueThenExcludesAllSecureHeaders() throws Exception {
		System.setProperty("security.headers.defaults.disabled", "true");
		this.spring.configLocations(this.xml("DefaultsDisabledWithPlaceholder")).autowire();
		// @formatter:off
		this.mvc.perform(get("/").secure(true))
				.andExpect(status().isOk())
				.andExpect(excludesDefaults());
		// @formatter:on
	}

	@Test
	public void requestWhenDefaultsDisabledWithPlaceholderFalseThenIncludeAllSecureHeaders() throws Exception {
		System.setProperty("security.headers.defaults.disabled", "false");
		this.spring.configLocations(this.xml("DefaultsDisabledWithPlaceholder")).autowire();
		// @formatter:off
		this.mvc.perform(get("/").secure(true))
				.andExpect(status().isOk())
				.andExpect(includesDefaults());
		// @formatter:on
	}

	@Test
	public void requestWhenDefaultsDisabledWithPlaceholderMissingThenIncludeAllSecureHeaders() throws Exception {
		System.clearProperty("security.headers.defaults.disabled");
		this.spring.configLocations(this.xml("DefaultsDisabledWithPlaceholder")).autowire();
		// @formatter:off
		this.mvc.perform(get("/").secure(true))
				.andExpect(status().isOk())
				.andExpect(includesDefaults());
		// @formatter:on
	}

	@Test
	public void requestWhenUsingContentTypeOptionsThenDefaultsToNoSniff() throws Exception {
		Set<String> excludedHeaders = new HashSet<>(defaultHeaders.keySet());
		excludedHeaders.remove("X-Content-Type-Options");
		this.spring.configLocations(this.xml("DefaultsDisabledWithContentTypeOptions")).autowire();
		// @formatter:off
		this.mvc.perform(get("/"))
				.andExpect(status().isOk())
				.andExpect(header().string("X-Content-Type-Options", "nosniff"))
				.andExpect(excludes(excludedHeaders));
		// @formatter:on
	}

	@Test
	public void requestWhenUsingFrameOptionsThenDefaultsToDeny() throws Exception {
		Set<String> excludedHeaders = new HashSet<>(defaultHeaders.keySet());
		excludedHeaders.remove("X-Frame-Options");
		this.spring.configLocations(this.xml("DefaultsDisabledWithFrameOptions")).autowire();
		// @formatter:off
		this.mvc.perform(get("/"))
				.andExpect(status().isOk())
				.andExpect(header().string("X-Frame-Options", "DENY"))
				.andExpect(excludes(excludedHeaders));
		// @formatter:on
	}

	@Test
	public void requestWhenUsingFrameOptionsDenyThenRespondsWithDeny() throws Exception {
		Set<String> excludedHeaders = new HashSet<>(defaultHeaders.keySet());
		excludedHeaders.remove("X-Frame-Options");
		this.spring.configLocations(this.xml("DefaultsDisabledWithFrameOptionsDeny")).autowire();
		// @formatter:off
		this.mvc.perform(get("/"))
				.andExpect(status().isOk())
				.andExpect(header().string("X-Frame-Options", "DENY"))
				.andExpect(excludes(excludedHeaders));
		// @formatter:on
	}

	@Test
	public void requestWhenUsingFrameOptionsSameOriginThenRespondsWithSameOrigin() throws Exception {
		Set<String> excludedHeaders = new HashSet<>(defaultHeaders.keySet());
		excludedHeaders.remove("X-Frame-Options");
		this.spring.configLocations(this.xml("DefaultsDisabledWithFrameOptionsSameOrigin")).autowire();
		// @formatter:off
		this.mvc.perform(get("/"))
				.andExpect(status().isOk())
				.andExpect(header().string("X-Frame-Options", "SAMEORIGIN"))
				.andExpect(excludes(excludedHeaders));
		// @formatter:on
	}

	@Test
	public void configureWhenUsingFrameOptionsAllowFromNoOriginThenAutowireFails() {
		assertThatExceptionOfType(BeanDefinitionParsingException.class)
				.isThrownBy(() -> this.spring
						.configLocations(this.xml("DefaultsDisabledWithFrameOptionsAllowFromNoOrigin")).autowire())
				.withMessageContaining("Strategy requires a 'value' to be set.");
		// FIXME better error message?
	}

	@Test
	public void configureWhenUsingFrameOptionsAllowFromBlankOriginThenAutowireFails() {
		assertThatExceptionOfType(BeanDefinitionParsingException.class)
				.isThrownBy(() -> this.spring
						.configLocations(this.xml("DefaultsDisabledWithFrameOptionsAllowFromBlankOrigin")).autowire())
				.withMessageContaining("Strategy requires a 'value' to be set.");
		// FIXME better error message?
	}

	@Test
	public void requestWhenUsingFrameOptionsAllowFromThenRespondsWithAllowFrom() throws Exception {
		Set<String> excludedHeaders = new HashSet<>(defaultHeaders.keySet());
		excludedHeaders.remove("X-Frame-Options");
		this.spring.configLocations(this.xml("DefaultsDisabledWithFrameOptionsAllowFrom")).autowire();
		// @formatter:off
		this.mvc.perform(get("/"))
				.andExpect(status().isOk())
				.andExpect(header().string("X-Frame-Options", "ALLOW-FROM https://example.org"))
				.andExpect(excludes(excludedHeaders));
		// @formatter:on
	}

	@Test
	public void requestWhenUsingFrameOptionsAllowFromWhitelistThenRespondsWithAllowFrom() throws Exception {
		Set<String> excludedHeaders = new HashSet<>(defaultHeaders.keySet());
		excludedHeaders.remove("X-Frame-Options");
		this.spring.configLocations(this.xml("DefaultsDisabledWithFrameOptionsAllowFromWhitelist")).autowire();
		// @formatter:off
		this.mvc.perform(get("/").param("from", "https://example.org"))
				.andExpect(status().isOk())
				.andExpect(header().string("X-Frame-Options", "ALLOW-FROM https://example.org"))
				.andExpect(excludes(excludedHeaders));
		this.mvc.perform(get("/"))
				.andExpect(status().isOk())
				.andExpect(header().string("X-Frame-Options", "DENY"))
				.andExpect(excludes(excludedHeaders));
		// @formatter:on
	}

	@Test
	public void requestWhenUsingCustomHeaderThenRespondsWithThatHeader() throws Exception {
		this.spring.configLocations(this.xml("DefaultsDisabledWithCustomHeader")).autowire();
		// @formatter:off
		this.mvc.perform(get("/"))
				.andExpect(status().isOk())
				.andExpect(header().string("a", "b"))
				.andExpect(header().string("c", "d"))
				.andExpect(excludesDefaults());
		// @formatter:on
	}

	@Test
	public void requestWhenUsingCustomHeaderWriterThenRespondsWithThatHeader() throws Exception {
		this.spring.configLocations(this.xml("DefaultsDisabledWithCustomHeaderWriter")).autowire();
		// @formatter:off
		this.mvc.perform(get("/"))
				.andExpect(status().isOk())
				.andExpect(header().string("abc", "def"))
				.andExpect(excludesDefaults());
		// @formatter:on
	}

	@Test
	public void configureWhenUsingCustomHeaderNameOnlyThenAutowireFails() {
		assertThatExceptionOfType(BeanCreationException.class).isThrownBy(
				() -> this.spring.configLocations(this.xml("DefaultsDisabledWithOnlyHeaderName")).autowire());
	}

	@Test
	public void configureWhenUsingCustomHeaderValueOnlyThenAutowireFails() {
		assertThatExceptionOfType(BeanCreationException.class).isThrownBy(
				() -> this.spring.configLocations(this.xml("DefaultsDisabledWithOnlyHeaderValue")).autowire());
	}

	@Test
	public void requestWhenUsingXssProtectionThenDefaultsToModeBlock() throws Exception {
		Set<String> excludedHeaders = new HashSet<>(defaultHeaders.keySet());
		excludedHeaders.remove("X-XSS-Protection");
		this.spring.configLocations(this.xml("DefaultsDisabledWithXssProtection")).autowire();
		// @formatter:off
		this.mvc.perform(get("/"))
				.andExpect(status().isOk())
				.andExpect(header().string("X-XSS-Protection", "1; mode=block"))
				.andExpect(excludes(excludedHeaders));
		// @formatter:on
	}

	@Test
	public void requestWhenEnablingXssProtectionThenDefaultsToModeBlock() throws Exception {
		Set<String> excludedHeaders = new HashSet<>(defaultHeaders.keySet());
		excludedHeaders.remove("X-XSS-Protection");
		this.spring.configLocations(this.xml("DefaultsDisabledWithXssProtectionEnabled")).autowire();
		// @formatter:off
		this.mvc.perform(get("/"))
				.andExpect(status().isOk())
				.andExpect(header().string("X-XSS-Protection", "1; mode=block"))
				.andExpect(excludes(excludedHeaders));
		// @formatter:on
	}

	@Test
	public void requestWhenDisablingXssProtectionThenDefaultsToZero() throws Exception {
		Set<String> excludedHeaders = new HashSet<>(defaultHeaders.keySet());
		excludedHeaders.remove("X-XSS-Protection");
		this.spring.configLocations(this.xml("DefaultsDisabledWithXssProtectionDisabled")).autowire();
		// @formatter:off
		this.mvc.perform(get("/"))
				.andExpect(status().isOk())
				.andExpect(header().string("X-XSS-Protection", "0"))
				.andExpect(excludes(excludedHeaders));
		// @formatter:on
	}

	@Test
	public void configureWhenXssProtectionDisabledAndBlockSetThenAutowireFails() {
		assertThatExceptionOfType(BeanCreationException.class)
				.isThrownBy(() -> this.spring
						.configLocations(this.xml("DefaultsDisabledWithXssProtectionDisabledAndBlockSet")).autowire())
				.withMessageContaining("Cannot set block to true with enabled false");
	}

	@Test
	public void requestWhenUsingCacheControlThenRespondsWithCorrespondingHeaders() throws Exception {
		Map<String, String> includedHeaders = ImmutableMap.<String, String>builder()
				.put("Cache-Control", "no-cache, no-store, max-age=0, must-revalidate").put("Expires", "0")
				.put("Pragma", "no-cache").build();
		this.spring.configLocations(this.xml("DefaultsDisabledWithCacheControl")).autowire();
		// @formatter:off
		this.mvc.perform(get("/"))
				.andExpect(status().isOk())
				.andExpect(includes(includedHeaders));
		// @formatter:on
	}

	@Test
	public void requestWhenUsingHstsThenRespondsWithHstsHeader() throws Exception {
		Set<String> excludedHeaders = new HashSet<>(defaultHeaders.keySet());
		excludedHeaders.remove("Strict-Transport-Security");
		this.spring.configLocations(this.xml("DefaultsDisabledWithHsts")).autowire();
		// @formatter:off
		this.mvc.perform(get("/").secure(true))
				.andExpect(status().isOk())
				.andExpect(header().string("Strict-Transport-Security", "max-age=31536000 ; includeSubDomains"))
				.andExpect(excludes(excludedHeaders));
		// @formatter:on
	}

	@Test
	public void insecureRequestWhenUsingHstsThenExcludesHstsHeader() throws Exception {
		this.spring.configLocations(this.xml("DefaultsDisabledWithHsts")).autowire();
		// @formatter:off
		this.mvc.perform(get("/"))
				.andExpect(status().isOk())
				.andExpect(excludesDefaults());
		// @formatter:on
	}

	@Test
	public void insecureRequestWhenUsingCustomHstsRequestMatcherThenIncludesHstsHeader() throws Exception {
		Set<String> excludedHeaders = new HashSet<>(defaultHeaders.keySet());
		excludedHeaders.remove("Strict-Transport-Security");
		this.spring.configLocations(this.xml("DefaultsDisabledWithCustomHstsRequestMatcher")).autowire();
		// @formatter:off
		this.mvc.perform(get("/"))
				.andExpect(status().isOk())
				.andExpect(header().string("Strict-Transport-Security", "max-age=1"))
				.andExpect(excludes(excludedHeaders));
		// @formatter:on
	}

	@Test
	public void configureWhenUsingHpkpWithoutPinsThenAutowireFails() {
		assertThatExceptionOfType(XmlBeanDefinitionStoreException.class)
				.isThrownBy(() -> this.spring.configLocations(this.xml("DefaultsDisabledWithEmptyHpkp")).autowire())
				.withMessageContaining("The content of element 'hpkp' is not complete");
	}

	@Test
	public void configureWhenUsingHpkpWithEmptyPinsThenAutowireFails() {
		assertThatExceptionOfType(XmlBeanDefinitionStoreException.class)
				.isThrownBy(() -> this.spring.configLocations(this.xml("DefaultsDisabledWithEmptyPins")).autowire())
				.withMessageContaining("The content of element 'pins' is not complete");
	}

	@Test
	public void requestWhenUsingHpkpThenIncludesHpkpHeader() throws Exception {
		this.spring.configLocations(this.xml("DefaultsDisabledWithHpkp")).autowire();
		// @formatter:off
		this.mvc.perform(get("/").secure(true))
				.andExpect(status().isOk())
				.andExpect(header().string("Public-Key-Pins-Report-Only",
						"max-age=5184000 ; pin-sha256=\"d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM=\""))
				.andExpect(excludesDefaults());
		// @formatter:on
	}

	@Test
	public void requestWhenUsingHpkpDefaultsThenIncludesHpkpHeaderUsingSha256() throws Exception {
		this.spring.configLocations(this.xml("DefaultsDisabledWithHpkpDefaults")).autowire();
		// @formatter:off
		this.mvc.perform(get("/").secure(true))
				.andExpect(status().isOk())
				.andExpect(header().string("Public-Key-Pins-Report-Only",
						"max-age=5184000 ; pin-sha256=\"d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM=\""))
				.andExpect(excludesDefaults());
		// @formatter:on
	}

	@Test
	public void insecureRequestWhenUsingHpkpThenExcludesHpkpHeader() throws Exception {
		this.spring.configLocations(this.xml("DefaultsDisabledWithHpkpDefaults")).autowire();
		// @formatter:off
		this.mvc.perform(get("/"))
				.andExpect(status().isOk())
				.andExpect(header().doesNotExist("Public-Key-Pins-Report-Only"))
				.andExpect(excludesDefaults());
		// @formatter:on
	}

	@Test
	public void requestWhenUsingHpkpCustomMaxAgeThenIncludesHpkpHeaderAccordingly() throws Exception {
		this.spring.configLocations(this.xml("DefaultsDisabledWithHpkpMaxAge")).autowire();
		// @formatter:off
		this.mvc.perform(get("/").secure(true))
				.andExpect(status().isOk())
				.andExpect(header().string("Public-Key-Pins-Report-Only",
						"max-age=604800 ; pin-sha256=\"d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM=\""))
				.andExpect(excludesDefaults());
		// @formatter:on
	}

	@Test
	public void requestWhenUsingHpkpReportThenIncludesHpkpHeaderAccordingly() throws Exception {
		this.spring.configLocations(this.xml("DefaultsDisabledWithHpkpReport")).autowire();
		// @formatter:off
		this.mvc.perform(get("/").secure(true))
				.andExpect(status().isOk())
				.andExpect(header().string("Public-Key-Pins",
						"max-age=5184000 ; pin-sha256=\"d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM=\""))
				.andExpect(excludesDefaults());
		// @formatter:on
	}

	@Test
	public void requestWhenUsingHpkpIncludeSubdomainsThenIncludesHpkpHeaderAccordingly() throws Exception {
		this.spring.configLocations(this.xml("DefaultsDisabledWithHpkpIncludeSubdomains")).autowire();
		// @formatter:off
		this.mvc.perform(get("/").secure(true))
				.andExpect(status().isOk())
				.andExpect(header().string("Public-Key-Pins-Report-Only",
					"max-age=5184000 ; pin-sha256=\"d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM=\" ; includeSubDomains"))
				.andExpect(excludesDefaults());
		// @formatter:on
	}

	@Test
	public void requestWhenUsingHpkpReportUriThenIncludesHpkpHeaderAccordingly() throws Exception {
		this.spring.configLocations(this.xml("DefaultsDisabledWithHpkpReportUri")).autowire();
		// @formatter:off
		this.mvc.perform(get("/").secure(true))
				.andExpect(status().isOk())
				.andExpect(header().string("Public-Key-Pins-Report-Only",
					"max-age=5184000 ; pin-sha256=\"d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM=\" ; report-uri=\"https://example.net/pkp-report\""))
				.andExpect(excludesDefaults());
		// @formatter:on
	}

	@Test
	public void requestWhenCacheControlDisabledThenExcludesHeader() throws Exception {
		Collection<String> cacheControl = Arrays.asList("Cache-Control", "Expires", "Pragma");
		Map<String, String> allButCacheControl = remove(defaultHeaders, cacheControl);
		this.spring.configLocations(this.xml("CacheControlDisabled")).autowire();
		// @formatter:off
		this.mvc.perform(get("/").secure(true))
				.andExpect(status().isOk())
				.andExpect(includes(allButCacheControl))
				.andExpect(excludes(cacheControl));
		// @formatter:on
	}

	@Test
	public void requestWhenContentTypeOptionsDisabledThenExcludesHeader() throws Exception {
		Collection<String> contentTypeOptions = Arrays.asList("X-Content-Type-Options");
		Map<String, String> allButContentTypeOptions = remove(defaultHeaders, contentTypeOptions);
		this.spring.configLocations(this.xml("ContentTypeOptionsDisabled")).autowire();
		// @formatter:off
		this.mvc.perform(get("/").secure(true))
				.andExpect(status().isOk())
				.andExpect(includes(allButContentTypeOptions))
				.andExpect(excludes(contentTypeOptions));
		// @formatter:on
	}

	@Test
	public void requestWhenHstsDisabledThenExcludesHeader() throws Exception {
		Collection<String> hsts = Arrays.asList("Strict-Transport-Security");
		Map<String, String> allButHsts = remove(defaultHeaders, hsts);
		this.spring.configLocations(this.xml("HstsDisabled")).autowire();
		// @formatter:off
		this.mvc.perform(get("/").secure(true))
				.andExpect(status().isOk())
				.andExpect(includes(allButHsts))
				.andExpect(excludes(hsts));
		// @formatter:on
	}

	@Test
	public void requestWhenHpkpDisabledThenExcludesHeader() throws Exception {
		this.spring.configLocations(this.xml("HpkpDisabled")).autowire();
		// @formatter:off
		this.mvc.perform(get("/").secure(true))
				.andExpect(status().isOk())
				.andExpect(includesDefaults());
		// @formatter:on
	}

	@Test
	public void requestWhenFrameOptionsDisabledThenExcludesHeader() throws Exception {
		Collection<String> frameOptions = Arrays.asList("X-Frame-Options");
		Map<String, String> allButFrameOptions = remove(defaultHeaders, frameOptions);
		this.spring.configLocations(this.xml("FrameOptionsDisabled")).autowire();
		// @formatter:off
		this.mvc.perform(get("/").secure(true))
				.andExpect(status().isOk())
				.andExpect(includes(allButFrameOptions))
				.andExpect(excludes(frameOptions));
		// @formatter:on
	}

	@Test
	public void requestWhenXssProtectionDisabledThenExcludesHeader() throws Exception {
		Collection<String> xssProtection = Arrays.asList("X-XSS-Protection");
		Map<String, String> allButXssProtection = remove(defaultHeaders, xssProtection);
		this.spring.configLocations(this.xml("XssProtectionDisabled")).autowire();
		// @formatter:off
		this.mvc.perform(get("/").secure(true))
				.andExpect(status().isOk())
				.andExpect(includes(allButXssProtection))
				.andExpect(excludes(xssProtection));
		// @formatter:on
	}

	@Test
	public void configureWhenHstsDisabledAndIncludeSubdomainsSpecifiedThenAutowireFails() {
		assertThatExceptionOfType(BeanDefinitionParsingException.class).isThrownBy(
				() -> this.spring.configLocations(this.xml("HstsDisabledSpecifyingIncludeSubdomains")).autowire())
				.withMessageContaining("include-subdomains");
	}

	@Test
	public void configureWhenHstsDisabledAndMaxAgeSpecifiedThenAutowireFails() {
		assertThatExceptionOfType(BeanDefinitionParsingException.class)
				.isThrownBy(() -> this.spring.configLocations(this.xml("HstsDisabledSpecifyingMaxAge")).autowire())
				.withMessageContaining("max-age");
	}

	@Test
	public void configureWhenHstsDisabledAndRequestMatcherSpecifiedThenAutowireFails() {
		assertThatExceptionOfType(BeanDefinitionParsingException.class)
				.isThrownBy(
						() -> this.spring.configLocations(this.xml("HstsDisabledSpecifyingRequestMatcher")).autowire())
				.withMessageContaining("request-matcher-ref");
	}

	@Test
	public void configureWhenXssProtectionDisabledAndEnabledThenAutowireFails() {
		assertThatExceptionOfType(BeanDefinitionParsingException.class)
				.isThrownBy(() -> this.spring.configLocations(this.xml("XssProtectionDisabledAndEnabled")).autowire())
				.withMessageContaining("enabled");
	}

	@Test
	public void configureWhenXssProtectionDisabledAndBlockSpecifiedThenAutowireFails() {
		assertThatExceptionOfType(BeanDefinitionParsingException.class)
				.isThrownBy(
						() -> this.spring.configLocations(this.xml("XssProtectionDisabledSpecifyingBlock")).autowire())
				.withMessageContaining("block");
	}

	@Test
	public void configureWhenFrameOptionsDisabledAndPolicySpecifiedThenAutowireFails() {
		assertThatExceptionOfType(BeanDefinitionParsingException.class)
				.isThrownBy(
						() -> this.spring.configLocations(this.xml("FrameOptionsDisabledSpecifyingPolicy")).autowire())
				.withMessageContaining("policy");
	}

	@Test
	public void requestWhenContentSecurityPolicyDirectivesConfiguredThenIncludesDirectives() throws Exception {
		Map<String, String> includedHeaders = new HashMap<>(defaultHeaders);
		includedHeaders.put("Content-Security-Policy", "default-src 'self'");
		this.spring.configLocations(this.xml("ContentSecurityPolicyWithPolicyDirectives")).autowire();
		// @formatter:off
		this.mvc.perform(get("/").secure(true))
				.andExpect(status().isOk())
				.andExpect(includes(includedHeaders));
		// @formatter:on
	}

	@Test
	public void requestWhenHeadersDisabledAndContentSecurityPolicyConfiguredThenExcludesHeader() throws Exception {
		this.spring.configLocations(this.xml("HeadersDisabledWithContentSecurityPolicy")).autowire();
		// @formatter:off
		this.mvc.perform(get("/"))
				.andExpect(status().isOk())
				.andExpect(excludesDefaults())
				.andExpect(excludes("Content-Security-Policy"));
		// @formatter:on
	}

	@Test
	public void requestWhenDefaultsDisabledAndContentSecurityPolicyConfiguredThenIncludesHeader() throws Exception {
		this.spring.configLocations(this.xml("DefaultsDisabledWithContentSecurityPolicy")).autowire();
		// @formatter:off
		this.mvc.perform(get("/"))
				.andExpect(status().isOk())
				.andExpect(excludesDefaults())
				.andExpect(header().string("Content-Security-Policy", "default-src 'self'"));
		// @formatter:on
	}

	@Test
	public void configureWhenContentSecurityPolicyConfiguredWithEmptyDirectivesThenAutowireFails() {
		assertThatExceptionOfType(BeanDefinitionParsingException.class).isThrownBy(
				() -> this.spring.configLocations(this.xml("ContentSecurityPolicyWithEmptyDirectives")).autowire());
	}

	@Test
	public void requestWhenContentSecurityPolicyConfiguredWithReportOnlyThenIncludesReportOnlyHeader()
			throws Exception {
		Map<String, String> includedHeaders = new HashMap<>(defaultHeaders);
		includedHeaders.put("Content-Security-Policy-Report-Only",
				"default-src https:; report-uri https://example.org/");
		this.spring.configLocations(this.xml("ContentSecurityPolicyWithReportOnly")).autowire();
		// @formatter:off
		this.mvc.perform(get("/").secure(true))
				.andExpect(status().isOk())
				.andExpect(includes(includedHeaders));
		// @formatter:on
	}

	@Test
	public void requestWhenReferrerPolicyConfiguredThenResponseDefaultsToNoReferrer() throws Exception {
		this.spring.configLocations(this.xml("DefaultsDisabledWithReferrerPolicy")).autowire();
		// @formatter:off
		this.mvc.perform(get("/"))
				.andExpect(status().isOk())
				.andExpect(excludesDefaults())
				.andExpect(header().string("Referrer-Policy", "no-referrer"));
		// @formatter:on
	}

	@Test
	public void requestWhenReferrerPolicyConfiguredWithSameOriginThenRespondsWithSameOrigin() throws Exception {
		this.spring.configLocations(this.xml("DefaultsDisabledWithReferrerPolicySameOrigin")).autowire();
		// @formatter:off
		this.mvc.perform(get("/"))
				.andExpect(status().isOk())
				.andExpect(excludesDefaults())
				.andExpect(header().string("Referrer-Policy", "same-origin"));
		// @formatter:on
	}

	private static ResultMatcher includesDefaults() {
		return includes(defaultHeaders);
	}

	private static ResultMatcher includes(Map<String, String> headers) {
		return (result) -> {
			for (Map.Entry<String, String> header : headers.entrySet()) {
				header().string(header.getKey(), header.getValue()).match(result);
			}
		};
	}

	private static ResultMatcher excludesDefaults() {
		return excludes(defaultHeaders.keySet());
	}

	private static ResultMatcher excludes(Collection<String> headers) {
		return (result) -> {
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
