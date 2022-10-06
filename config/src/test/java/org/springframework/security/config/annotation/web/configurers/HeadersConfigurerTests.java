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

import java.net.URI;
import java.util.LinkedHashMap;
import java.util.Map;

import com.google.common.net.HttpHeaders;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import org.springframework.beans.factory.BeanCreationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.test.SpringTestContext;
import org.springframework.security.config.test.SpringTestContextExtension;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.header.writers.CrossOriginEmbedderPolicyHeaderWriter;
import org.springframework.security.web.header.writers.CrossOriginOpenerPolicyHeaderWriter;
import org.springframework.security.web.header.writers.CrossOriginResourcePolicyHeaderWriter;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter.ReferrerPolicy;
import org.springframework.security.web.header.writers.XXssProtectionHeaderWriter;
import org.springframework.security.web.header.writers.frameoptions.XFrameOptionsHeaderWriter.XFrameOptionsMode;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultMatcher;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.springframework.security.config.Customizer.withDefaults;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;

/**
 * Tests for {@link HeadersConfigurer}.
 *
 * @author Rob Winch
 * @author Tim Ysewyn
 * @author Joe Grandja
 * @author Eddú Meléndez
 * @author Vedran Pavic
 * @author Eleftheria Stein
 * @author Marcus Da Coregio
 * @author Daniel Garnier-Moiroux
 */
@ExtendWith(SpringTestContextExtension.class)
public class HeadersConfigurerTests {

	public final SpringTestContext spring = new SpringTestContext(this);

	@Autowired
	MockMvc mvc;

	@Test
	public void getWhenHeadersConfiguredThenDefaultHeadersInResponse() throws Exception {
		this.spring.register(HeadersConfig.class).autowire();
		MvcResult mvcResult = this.mvc.perform(get("/").secure(true))
				.andExpect(header().string(HttpHeaders.X_CONTENT_TYPE_OPTIONS, "nosniff"))
				.andExpect(header().string(HttpHeaders.X_FRAME_OPTIONS, XFrameOptionsMode.DENY.name()))
				.andExpect(
						header().string(HttpHeaders.STRICT_TRANSPORT_SECURITY, "max-age=31536000 ; includeSubDomains"))
				.andExpect(header().string(HttpHeaders.CACHE_CONTROL, "no-cache, no-store, max-age=0, must-revalidate"))
				.andExpect(header().string(HttpHeaders.EXPIRES, "0"))
				.andExpect(header().string(HttpHeaders.PRAGMA, "no-cache"))
				.andExpect(header().string(HttpHeaders.X_XSS_PROTECTION, "0")).andReturn();
		assertThat(mvcResult.getResponse().getHeaderNames()).containsExactlyInAnyOrder(
				HttpHeaders.X_CONTENT_TYPE_OPTIONS, HttpHeaders.X_FRAME_OPTIONS, HttpHeaders.STRICT_TRANSPORT_SECURITY,
				HttpHeaders.CACHE_CONTROL, HttpHeaders.EXPIRES, HttpHeaders.PRAGMA, HttpHeaders.X_XSS_PROTECTION);
	}

	@Test
	public void getWhenHeadersConfiguredInLambdaThenDefaultHeadersInResponse() throws Exception {
		this.spring.register(HeadersInLambdaConfig.class).autowire();
		MvcResult mvcResult = this.mvc.perform(get("/").secure(true))
				.andExpect(header().string(HttpHeaders.X_CONTENT_TYPE_OPTIONS, "nosniff"))
				.andExpect(header().string(HttpHeaders.X_FRAME_OPTIONS, XFrameOptionsMode.DENY.name()))
				.andExpect(
						header().string(HttpHeaders.STRICT_TRANSPORT_SECURITY, "max-age=31536000 ; includeSubDomains"))
				.andExpect(header().string(HttpHeaders.CACHE_CONTROL, "no-cache, no-store, max-age=0, must-revalidate"))
				.andExpect(header().string(HttpHeaders.EXPIRES, "0"))
				.andExpect(header().string(HttpHeaders.PRAGMA, "no-cache"))
				.andExpect(header().string(HttpHeaders.X_XSS_PROTECTION, "0")).andReturn();
		assertThat(mvcResult.getResponse().getHeaderNames()).containsExactlyInAnyOrder(
				HttpHeaders.X_CONTENT_TYPE_OPTIONS, HttpHeaders.X_FRAME_OPTIONS, HttpHeaders.STRICT_TRANSPORT_SECURITY,
				HttpHeaders.CACHE_CONTROL, HttpHeaders.EXPIRES, HttpHeaders.PRAGMA, HttpHeaders.X_XSS_PROTECTION);
	}

	@Test
	public void getWhenHeaderDefaultsDisabledAndContentTypeConfiguredThenOnlyContentTypeHeaderInResponse()
			throws Exception {
		this.spring.register(ContentTypeOptionsConfig.class).autowire();
		MvcResult mvcResult = this.mvc.perform(get("/"))
				.andExpect(header().string(HttpHeaders.X_CONTENT_TYPE_OPTIONS, "nosniff")).andReturn();
		assertThat(mvcResult.getResponse().getHeaderNames()).containsExactly(HttpHeaders.X_CONTENT_TYPE_OPTIONS);
	}

	@Test
	public void getWhenOnlyContentTypeConfiguredInLambdaThenOnlyContentTypeHeaderInResponse() throws Exception {
		this.spring.register(ContentTypeOptionsInLambdaConfig.class).autowire();
		MvcResult mvcResult = this.mvc.perform(get("/"))
				.andExpect(header().string(HttpHeaders.X_CONTENT_TYPE_OPTIONS, "nosniff")).andReturn();
		assertThat(mvcResult.getResponse().getHeaderNames()).containsExactly(HttpHeaders.X_CONTENT_TYPE_OPTIONS);
	}

	@Test
	public void getWhenHeaderDefaultsDisabledAndFrameOptionsConfiguredThenOnlyFrameOptionsHeaderInResponse()
			throws Exception {
		this.spring.register(FrameOptionsConfig.class).autowire();
		MvcResult mvcResult = this.mvc.perform(get("/"))
				.andExpect(header().string(HttpHeaders.X_FRAME_OPTIONS, XFrameOptionsMode.DENY.name())).andReturn();
		assertThat(mvcResult.getResponse().getHeaderNames()).containsExactly(HttpHeaders.X_FRAME_OPTIONS);
	}

	@Test
	public void getWhenHeaderDefaultsDisabledAndHstsConfiguredThenOnlyStrictTransportSecurityHeaderInResponse()
			throws Exception {
		this.spring.register(HstsConfig.class).autowire();
		MvcResult mvcResult = this.mvc.perform(get("/").secure(true))
				.andExpect(
						header().string(HttpHeaders.STRICT_TRANSPORT_SECURITY, "max-age=31536000 ; includeSubDomains"))
				.andReturn();
		assertThat(mvcResult.getResponse().getHeaderNames()).containsExactly(HttpHeaders.STRICT_TRANSPORT_SECURITY);
	}

	@Test
	public void getWhenHeaderDefaultsDisabledAndCacheControlConfiguredThenCacheControlAndExpiresAndPragmaHeadersInResponse()
			throws Exception {
		this.spring.register(CacheControlConfig.class).autowire();
		MvcResult mvcResult = this.mvc.perform(get("/").secure(true))
				.andExpect(header().string(HttpHeaders.CACHE_CONTROL, "no-cache, no-store, max-age=0, must-revalidate"))
				.andExpect(header().string(HttpHeaders.EXPIRES, "0"))
				.andExpect(header().string(HttpHeaders.PRAGMA, "no-cache")).andReturn();
		assertThat(mvcResult.getResponse().getHeaderNames()).containsExactlyInAnyOrder(HttpHeaders.CACHE_CONTROL,
				HttpHeaders.EXPIRES, HttpHeaders.PRAGMA);
	}

	@Test
	public void getWhenOnlyCacheControlConfiguredInLambdaThenCacheControlAndExpiresAndPragmaHeadersInResponse()
			throws Exception {
		this.spring.register(CacheControlInLambdaConfig.class).autowire();
		MvcResult mvcResult = this.mvc.perform(get("/").secure(true))
				.andExpect(header().string(HttpHeaders.CACHE_CONTROL, "no-cache, no-store, max-age=0, must-revalidate"))
				.andExpect(header().string(HttpHeaders.EXPIRES, "0"))
				.andExpect(header().string(HttpHeaders.PRAGMA, "no-cache")).andReturn();
		assertThat(mvcResult.getResponse().getHeaderNames()).containsExactlyInAnyOrder(HttpHeaders.CACHE_CONTROL,
				HttpHeaders.EXPIRES, HttpHeaders.PRAGMA);
	}

	@Test
	public void getWhenHeaderDefaultsDisabledAndXssProtectionConfiguredThenOnlyXssProtectionHeaderInResponse()
			throws Exception {
		this.spring.register(XssProtectionConfig.class).autowire();
		MvcResult mvcResult = this.mvc.perform(get("/").secure(true))
				.andExpect(header().string(HttpHeaders.X_XSS_PROTECTION, "0")).andReturn();
		assertThat(mvcResult.getResponse().getHeaderNames()).containsExactly(HttpHeaders.X_XSS_PROTECTION);
	}

	@Test
	public void getWhenHeaderDefaultsDisabledAndXssProtectionConfiguredEnabledModeBlockThenOnlyXssProtectionHeaderInResponse()
			throws Exception {
		this.spring.register(XssProtectionValueEnabledModeBlockConfig.class).autowire();
		MvcResult mvcResult = this.mvc.perform(get("/").secure(true))
				.andExpect(header().string(HttpHeaders.X_XSS_PROTECTION, "1; mode=block")).andReturn();
		assertThat(mvcResult.getResponse().getHeaderNames()).containsExactly(HttpHeaders.X_XSS_PROTECTION);
	}

	@Test
	public void getWhenOnlyXssProtectionConfiguredInLambdaThenOnlyXssProtectionHeaderInResponse() throws Exception {
		this.spring.register(XssProtectionInLambdaConfig.class).autowire();
		MvcResult mvcResult = this.mvc.perform(get("/").secure(true))
				.andExpect(header().string(HttpHeaders.X_XSS_PROTECTION, "0")).andReturn();
		assertThat(mvcResult.getResponse().getHeaderNames()).containsExactly(HttpHeaders.X_XSS_PROTECTION);
	}

	@Test
	public void getWhenHeaderDefaultsDisabledAndXssProtectionConfiguredValueEnabledModeBlockInLambdaThenOnlyXssProtectionHeaderInResponse()
			throws Exception {
		this.spring.register(XssProtectionValueEnabledModeBlockInLambdaConfig.class).autowire();
		MvcResult mvcResult = this.mvc.perform(get("/").secure(true))
				.andExpect(header().string(HttpHeaders.X_XSS_PROTECTION, "1; mode=block")).andReturn();
		assertThat(mvcResult.getResponse().getHeaderNames()).containsExactly(HttpHeaders.X_XSS_PROTECTION);
	}

	@Test
	public void getWhenFrameOptionsSameOriginConfiguredThenFrameOptionsHeaderHasValueSameOrigin() throws Exception {
		this.spring.register(HeadersCustomSameOriginConfig.class).autowire();
		this.mvc.perform(get("/").secure(true))
				.andExpect(header().string(HttpHeaders.X_FRAME_OPTIONS, XFrameOptionsMode.SAMEORIGIN.name()))
				.andReturn();
	}

	@Test
	public void getWhenFrameOptionsSameOriginConfiguredInLambdaThenFrameOptionsHeaderHasValueSameOrigin()
			throws Exception {
		this.spring.register(HeadersCustomSameOriginInLambdaConfig.class).autowire();
		this.mvc.perform(get("/").secure(true))
				.andExpect(header().string(HttpHeaders.X_FRAME_OPTIONS, XFrameOptionsMode.SAMEORIGIN.name()))
				.andReturn();
	}

	@Test
	public void getWhenHeaderDefaultsDisabledAndPublicHpkpWithNoPinThenNoHeadersInResponse() throws Exception {
		this.spring.register(HpkpConfigNoPins.class).autowire();
		MvcResult mvcResult = this.mvc.perform(get("/")).andReturn();
		assertThat(mvcResult.getResponse().getHeaderNames()).isEmpty();
	}

	@Test
	public void getWhenSecureRequestAndHpkpWithPinThenPublicKeyPinsReportOnlyHeaderInResponse() throws Exception {
		this.spring.register(HpkpConfig.class).autowire();
		ResultMatcher pinsReportOnly = header().string(HttpHeaders.PUBLIC_KEY_PINS_REPORT_ONLY,
				"max-age=5184000 ; pin-sha256=\"d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM=\"");
		// @formatter:off
		MvcResult mvcResult = this.mvc.perform(get("/").secure(true))
				.andExpect(pinsReportOnly)
				.andReturn();
		// @formatter:on
		assertThat(mvcResult.getResponse().getHeaderNames()).containsExactly(HttpHeaders.PUBLIC_KEY_PINS_REPORT_ONLY);
	}

	@Test
	public void getWhenInsecureRequestHeaderDefaultsDisabledAndHpkpWithPinThenNoHeadersInResponse() throws Exception {
		this.spring.register(HpkpConfig.class).autowire();
		MvcResult mvcResult = this.mvc.perform(get("/")).andReturn();
		assertThat(mvcResult.getResponse().getHeaderNames()).isEmpty();
	}

	@Test
	public void getWhenHpkpWithMultiplePinsThenPublicKeyPinsReportOnlyHeaderWithMultiplePinsInResponse()
			throws Exception {
		this.spring.register(HpkpConfigWithPins.class).autowire();
		ResultMatcher pinsReportOnly = header().string(HttpHeaders.PUBLIC_KEY_PINS_REPORT_ONLY,
				"max-age=5184000 ; pin-sha256=\"d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM=\" ; pin-sha256=\"E9CZ9INDbd+2eRQozYqqbQ2yXLVKB9+xcprMF+44U1g=\"");
		// @formatter:off
		MvcResult mvcResult = this.mvc.perform(get("/").secure(true))
				.andExpect(pinsReportOnly)
				.andReturn();
		// @formatter:on
		assertThat(mvcResult.getResponse().getHeaderNames()).containsExactly(HttpHeaders.PUBLIC_KEY_PINS_REPORT_ONLY);
	}

	@Test
	public void getWhenHpkpWithCustomAgeThenPublicKeyPinsReportOnlyHeaderWithCustomAgeInResponse() throws Exception {
		this.spring.register(HpkpConfigCustomAge.class).autowire();
		ResultMatcher pinsReportOnly = header().string(HttpHeaders.PUBLIC_KEY_PINS_REPORT_ONLY,
				"max-age=604800 ; pin-sha256=\"d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM=\"");
		// @formatter:off
		MvcResult mvcResult = this.mvc.perform(get("/").secure(true))
				.andExpect(pinsReportOnly)
				.andReturn();
		// @formatter:on
		assertThat(mvcResult.getResponse().getHeaderNames()).containsExactly(HttpHeaders.PUBLIC_KEY_PINS_REPORT_ONLY);
	}

	@Test
	public void getWhenHpkpWithReportOnlyFalseThenPublicKeyPinsHeaderInResponse() throws Exception {
		this.spring.register(HpkpConfigTerminateConnection.class).autowire();
		ResultMatcher pins = header().string(HttpHeaders.PUBLIC_KEY_PINS,
				"max-age=5184000 ; pin-sha256=\"d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM=\"");
		// @formatter:off
		MvcResult mvcResult = this.mvc.perform(get("/").secure(true))
				.andExpect(pins)
				.andReturn();
		// @formatter:on
		assertThat(mvcResult.getResponse().getHeaderNames()).containsExactly(HttpHeaders.PUBLIC_KEY_PINS);
	}

	@Test
	public void getWhenHpkpIncludeSubdomainThenPublicKeyPinsReportOnlyHeaderWithIncludeSubDomainsInResponse()
			throws Exception {
		this.spring.register(HpkpConfigIncludeSubDomains.class).autowire();
		ResultMatcher pinsReportOnly = header().string(HttpHeaders.PUBLIC_KEY_PINS_REPORT_ONLY,
				"max-age=5184000 ; pin-sha256=\"d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM=\" ; includeSubDomains");
		// @formatter:off
		MvcResult mvcResult = this.mvc.perform(get("/").secure(true))
				.andExpect(pinsReportOnly)
				.andReturn();
		// @formatter:on
		assertThat(mvcResult.getResponse().getHeaderNames()).containsExactly(HttpHeaders.PUBLIC_KEY_PINS_REPORT_ONLY);
	}

	@Test
	public void getWhenHpkpWithReportUriThenPublicKeyPinsReportOnlyHeaderWithReportUriInResponse() throws Exception {
		this.spring.register(HpkpConfigWithReportURI.class).autowire();
		ResultMatcher pinsReportOnly = header().string(HttpHeaders.PUBLIC_KEY_PINS_REPORT_ONLY,
				"max-age=5184000 ; pin-sha256=\"d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM=\" ; report-uri=\"https://example.net/pkp-report\"");
		// @formatter:off
		MvcResult mvcResult = this.mvc.perform(get("/").secure(true))
				.andExpect(pinsReportOnly)
				.andReturn();
		// @formatter:on
		assertThat(mvcResult.getResponse().getHeaderNames()).containsExactly(HttpHeaders.PUBLIC_KEY_PINS_REPORT_ONLY);
	}

	@Test
	public void getWhenHpkpWithReportUriAsStringThenPublicKeyPinsReportOnlyHeaderWithReportUriInResponse()
			throws Exception {
		this.spring.register(HpkpConfigWithReportURIAsString.class).autowire();
		ResultMatcher pinsReportOnly = header().string(HttpHeaders.PUBLIC_KEY_PINS_REPORT_ONLY,
				"max-age=5184000 ; pin-sha256=\"d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM=\" ; report-uri=\"https://example.net/pkp-report\"");
		// @formatter:off
		MvcResult mvcResult = this.mvc.perform(get("/").secure(true))
				.andExpect(pinsReportOnly)
				.andReturn();
		// @formatter:on
		assertThat(mvcResult.getResponse().getHeaderNames()).containsExactly(HttpHeaders.PUBLIC_KEY_PINS_REPORT_ONLY);
	}

	@Test
	public void getWhenHpkpWithReportUriInLambdaThenPublicKeyPinsReportOnlyHeaderWithReportUriInResponse()
			throws Exception {
		this.spring.register(HpkpWithReportUriInLambdaConfig.class).autowire();
		ResultMatcher pinsReportOnly = header().string(HttpHeaders.PUBLIC_KEY_PINS_REPORT_ONLY,
				"max-age=5184000 ; pin-sha256=\"d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM=\" ; report-uri=\"https://example.net/pkp-report\"");
		// @formatter:off
		MvcResult mvcResult = this.mvc.perform(get("/").secure(true))
				.andExpect(pinsReportOnly)
				.andReturn();
		// @formatter:on
		assertThat(mvcResult.getResponse().getHeaderNames()).containsExactly(HttpHeaders.PUBLIC_KEY_PINS_REPORT_ONLY);
	}

	@Test
	public void getWhenContentSecurityPolicyConfiguredThenContentSecurityPolicyHeaderInResponse() throws Exception {
		this.spring.register(ContentSecurityPolicyDefaultConfig.class).autowire();
		ResultMatcher csp = header().string(HttpHeaders.CONTENT_SECURITY_POLICY, "default-src 'self'");
		// @formatter:off
		MvcResult mvcResult = this.mvc.perform(get("/").secure(true))
				.andExpect(csp)
				.andReturn();
		// @formatter:on
		assertThat(mvcResult.getResponse().getHeaderNames()).containsExactly(HttpHeaders.CONTENT_SECURITY_POLICY);
	}

	@Test
	public void getWhenContentSecurityPolicyWithReportOnlyThenContentSecurityPolicyReportOnlyHeaderInResponse()
			throws Exception {
		this.spring.register(ContentSecurityPolicyReportOnlyConfig.class).autowire();
		ResultMatcher cspReportOnly = header().string(HttpHeaders.CONTENT_SECURITY_POLICY_REPORT_ONLY,
				"default-src 'self'; script-src trustedscripts.example.com");
		// @formatter:off
		MvcResult mvcResult = this.mvc.perform(get("/").secure(true))
				.andExpect(cspReportOnly)
				.andReturn();
		// @formatter:on
		assertThat(mvcResult.getResponse().getHeaderNames())
				.containsExactly(HttpHeaders.CONTENT_SECURITY_POLICY_REPORT_ONLY);
	}

	@Test
	public void getWhenContentSecurityPolicyWithReportOnlyInLambdaThenContentSecurityPolicyReportOnlyHeaderInResponse()
			throws Exception {
		this.spring.register(ContentSecurityPolicyReportOnlyInLambdaConfig.class).autowire();
		ResultMatcher csp = header().string(HttpHeaders.CONTENT_SECURITY_POLICY_REPORT_ONLY,
				"default-src 'self'; script-src trustedscripts.example.com");
		// @formatter:off
		MvcResult mvcResult = this.mvc.perform(get("/").secure(true))
				.andExpect(csp)
				.andReturn();
		// @formatter:on
		assertThat(mvcResult.getResponse().getHeaderNames())
				.containsExactly(HttpHeaders.CONTENT_SECURITY_POLICY_REPORT_ONLY);
	}

	@Test
	public void configureWhenContentSecurityPolicyEmptyThenException() {
		assertThatExceptionOfType(BeanCreationException.class)
				.isThrownBy(() -> this.spring.register(ContentSecurityPolicyInvalidConfig.class).autowire())
				.withRootCauseInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void configureWhenContentSecurityPolicyEmptyInLambdaThenException() {
		assertThatExceptionOfType(BeanCreationException.class)
				.isThrownBy(() -> this.spring.register(ContentSecurityPolicyInvalidInLambdaConfig.class).autowire())
				.withRootCauseInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void configureWhenContentSecurityPolicyNoPolicyDirectivesInLambdaThenDefaultHeaderValue() throws Exception {
		this.spring.register(ContentSecurityPolicyNoDirectivesInLambdaConfig.class).autowire();
		ResultMatcher csp = header().string(HttpHeaders.CONTENT_SECURITY_POLICY, "default-src 'self'");
		// @formatter:off
		MvcResult mvcResult = this.mvc.perform(get("/").secure(true))
				.andExpect(csp)
				.andReturn();
		// @formatter:on
		assertThat(mvcResult.getResponse().getHeaderNames()).containsExactly(HttpHeaders.CONTENT_SECURITY_POLICY);
	}

	@Test
	public void getWhenReferrerPolicyConfiguredThenReferrerPolicyHeaderInResponse() throws Exception {
		this.spring.register(ReferrerPolicyDefaultConfig.class).autowire();
		ResultMatcher referrerPolicy = header().string("Referrer-Policy", ReferrerPolicy.NO_REFERRER.getPolicy());
		// @formatter:off
		MvcResult mvcResult = this.mvc.perform(get("/").secure(true))
				.andExpect(referrerPolicy)
				.andReturn();
		// @formatter:on
		assertThat(mvcResult.getResponse().getHeaderNames()).containsExactly("Referrer-Policy");
	}

	@Test
	public void getWhenReferrerPolicyInLambdaThenReferrerPolicyHeaderInResponse() throws Exception {
		this.spring.register(ReferrerPolicyDefaultInLambdaConfig.class).autowire();
		ResultMatcher referrerPolicy = header().string("Referrer-Policy", ReferrerPolicy.NO_REFERRER.getPolicy());
		// @formatter:off
		MvcResult mvcResult = this.mvc.perform(get("/").secure(true))
				.andExpect(referrerPolicy)
				.andReturn();
		// @formatter:on
		assertThat(mvcResult.getResponse().getHeaderNames()).containsExactly("Referrer-Policy");
	}

	@Test
	public void getWhenReferrerPolicyConfiguredWithCustomValueThenReferrerPolicyHeaderWithCustomValueInResponse()
			throws Exception {
		this.spring.register(ReferrerPolicyCustomConfig.class).autowire();
		ResultMatcher referrerPolicy = header().string("Referrer-Policy", ReferrerPolicy.SAME_ORIGIN.getPolicy());
		// @formatter:off
		MvcResult mvcResult = this.mvc.perform(get("/").secure(true))
				.andExpect(referrerPolicy)
				.andReturn();
		// @formatter:on
		assertThat(mvcResult.getResponse().getHeaderNames()).containsExactly("Referrer-Policy");
	}

	@Test
	public void getWhenReferrerPolicyConfiguredWithCustomValueInLambdaThenCustomValueInResponse() throws Exception {
		this.spring.register(ReferrerPolicyCustomInLambdaConfig.class).autowire();
		ResultMatcher referrerPolicy = header().string("Referrer-Policy", ReferrerPolicy.SAME_ORIGIN.getPolicy());
		// @formatter:off
		MvcResult mvcResult = this.mvc.perform(get("/").secure(true))
				.andExpect(referrerPolicy)
				.andReturn();
		// @formatter:on
		assertThat(mvcResult.getResponse().getHeaderNames()).containsExactly("Referrer-Policy");
	}

	@Test
	public void getWhenFeaturePolicyConfiguredThenFeaturePolicyHeaderInResponse() throws Exception {
		this.spring.register(FeaturePolicyConfig.class).autowire();
		ResultMatcher featurePolicy = header().string("Feature-Policy", "geolocation 'self'");
		// @formatter:off
		MvcResult mvcResult = this.mvc.perform(get("/").secure(true))
				.andExpect(featurePolicy)
				.andReturn();
		// @formatter:on
		assertThat(mvcResult.getResponse().getHeaderNames()).containsExactly("Feature-Policy");
	}

	@Test
	public void configureWhenFeaturePolicyEmptyThenException() {
		assertThatExceptionOfType(BeanCreationException.class)
				.isThrownBy(() -> this.spring.register(FeaturePolicyInvalidConfig.class).autowire())
				.withRootCauseInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void getWhenPermissionsPolicyConfiguredThenPermissionsPolicyHeaderInResponse() throws Exception {
		this.spring.register(PermissionsPolicyConfig.class).autowire();
		ResultMatcher permissionsPolicy = header().string("Permissions-Policy", "geolocation=(self)");
		// @formatter:off
		MvcResult mvcResult = this.mvc.perform(get("/").secure(true))
				.andExpect(permissionsPolicy)
				.andReturn();
		// @formatter:on
		assertThat(mvcResult.getResponse().getHeaderNames()).containsExactly("Permissions-Policy");
	}

	@Test
	public void getWhenPermissionsPolicyConfiguredWithStringThenPermissionsPolicyHeaderInResponse() throws Exception {
		this.spring.register(PermissionsPolicyStringConfig.class).autowire();
		ResultMatcher permissionsPolicy = header().string("Permissions-Policy", "geolocation=(self)");
		// @formatter:off
		MvcResult mvcResult = this.mvc.perform(get("/").secure(true))
				.andExpect(permissionsPolicy)
				.andReturn();
		// @formatter:on
		assertThat(mvcResult.getResponse().getHeaderNames()).containsExactly("Permissions-Policy");
	}

	@Test
	public void configureWhenPermissionsPolicyEmptyThenException() {
		assertThatExceptionOfType(BeanCreationException.class)
				.isThrownBy(() -> this.spring.register(PermissionsPolicyInvalidConfig.class).autowire())
				.withRootCauseInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void configureWhenPermissionsPolicyStringEmptyThenException() {
		assertThatExceptionOfType(BeanCreationException.class)
				.isThrownBy(() -> this.spring.register(PermissionsPolicyInvalidStringConfig.class).autowire())
				.withRootCauseInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void getWhenHstsConfiguredWithPreloadThenStrictTransportSecurityHeaderWithPreloadInResponse()
			throws Exception {
		this.spring.register(HstsWithPreloadConfig.class).autowire();
		ResultMatcher hsts = header().string(HttpHeaders.STRICT_TRANSPORT_SECURITY,
				"max-age=31536000 ; includeSubDomains ; preload");
		// @formatter:off
		MvcResult mvcResult = this.mvc.perform(get("/").secure(true))
				.andExpect(hsts)
				.andReturn();
		// @formatter:on
		assertThat(mvcResult.getResponse().getHeaderNames()).containsExactly(HttpHeaders.STRICT_TRANSPORT_SECURITY);
	}

	@Test
	public void getWhenHstsConfiguredWithPreloadInLambdaThenStrictTransportSecurityHeaderWithPreloadInResponse()
			throws Exception {
		this.spring.register(HstsWithPreloadInLambdaConfig.class).autowire();
		ResultMatcher hsts = header().string(HttpHeaders.STRICT_TRANSPORT_SECURITY,
				"max-age=31536000 ; includeSubDomains ; preload");
		// @formatter:off
		MvcResult mvcResult = this.mvc.perform(get("/").secure(true))
				.andExpect(hsts)
				.andReturn();
		// @formatter:on
		assertThat(mvcResult.getResponse().getHeaderNames()).containsExactly(HttpHeaders.STRICT_TRANSPORT_SECURITY);
	}

	@Test
	public void getWhenCustomCrossOriginPoliciesInLambdaThenCrossOriginPolicyHeadersWithCustomValuesInResponse()
			throws Exception {
		this.spring.register(CrossOriginCustomPoliciesInLambdaConfig.class).autowire();
		MvcResult mvcResult = this.mvc.perform(get("/"))
				.andExpect(header().string(HttpHeaders.CROSS_ORIGIN_OPENER_POLICY, "same-origin"))
				.andExpect(header().string(HttpHeaders.CROSS_ORIGIN_EMBEDDER_POLICY, "require-corp"))
				.andExpect(header().string(HttpHeaders.CROSS_ORIGIN_RESOURCE_POLICY, "same-origin")).andReturn();
		assertThat(mvcResult.getResponse().getHeaderNames()).containsExactly(HttpHeaders.CROSS_ORIGIN_OPENER_POLICY,
				HttpHeaders.CROSS_ORIGIN_EMBEDDER_POLICY, HttpHeaders.CROSS_ORIGIN_RESOURCE_POLICY);
	}

	@Test
	public void getWhenCustomCrossOriginPoliciesThenCrossOriginPolicyHeadersWithCustomValuesInResponse()
			throws Exception {
		this.spring.register(CrossOriginCustomPoliciesConfig.class).autowire();
		MvcResult mvcResult = this.mvc.perform(get("/"))
				.andExpect(header().string(HttpHeaders.CROSS_ORIGIN_OPENER_POLICY, "same-origin"))
				.andExpect(header().string(HttpHeaders.CROSS_ORIGIN_EMBEDDER_POLICY, "require-corp"))
				.andExpect(header().string(HttpHeaders.CROSS_ORIGIN_RESOURCE_POLICY, "same-origin")).andReturn();
		assertThat(mvcResult.getResponse().getHeaderNames()).containsExactly(HttpHeaders.CROSS_ORIGIN_OPENER_POLICY,
				HttpHeaders.CROSS_ORIGIN_EMBEDDER_POLICY, HttpHeaders.CROSS_ORIGIN_RESOURCE_POLICY);
	}

	@Configuration
	@EnableWebSecurity
	static class HeadersConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.headers();
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class HeadersInLambdaConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.headers(withDefaults());
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class ContentTypeOptionsConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.headers()
					.defaultsDisabled()
					.contentTypeOptions();
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class ContentTypeOptionsInLambdaConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.headers((headers) ->
					headers
						.defaultsDisabled()
						.contentTypeOptions(withDefaults())
				);
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class FrameOptionsConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.headers()
					.defaultsDisabled()
					.frameOptions();
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class HstsConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.headers()
					.defaultsDisabled()
					.httpStrictTransportSecurity();
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class CacheControlConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.headers()
					.defaultsDisabled()
					.cacheControl();
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class CacheControlInLambdaConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.headers((headers) ->
					headers
						.defaultsDisabled()
						.cacheControl(withDefaults())
				);
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class XssProtectionConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.headers()
					.defaultsDisabled()
					.xssProtection();
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class XssProtectionValueEnabledModeBlockConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.headers()
					.defaultsDisabled()
					.xssProtection()
					.headerValue(XXssProtectionHeaderWriter.HeaderValue.ENABLED_MODE_BLOCK);
			// @formatter:on
			return http.build();
		}

	}

	@EnableWebSecurity
	static class XssProtectionInLambdaConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.headers((headers) ->
					headers
						.defaultsDisabled()
						.xssProtection(withDefaults())
				);
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class XssProtectionValueEnabledModeBlockInLambdaConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.headers((headers) ->
					headers
						.defaultsDisabled()
						.xssProtection((xXssConfig) ->
							xXssConfig.headerValue(XXssProtectionHeaderWriter.HeaderValue.ENABLED_MODE_BLOCK)
						)
				);
			// @formatter:on
			return http.build();
		}

	}

	@EnableWebSecurity
	static class HeadersCustomSameOriginConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.headers()
					.frameOptions().sameOrigin();
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class HeadersCustomSameOriginInLambdaConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.headers((headers) ->
					headers
						.frameOptions((frameOptionsConfig) -> frameOptionsConfig.sameOrigin())
				);
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class HpkpConfigNoPins {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.headers()
					.defaultsDisabled()
					.httpPublicKeyPinning();
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class HpkpConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.headers()
					.defaultsDisabled()
					.httpPublicKeyPinning()
						.addSha256Pins("d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM=");
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class HpkpConfigWithPins {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			Map<String, String> pins = new LinkedHashMap<>();
			pins.put("d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM=", "sha256");
			pins.put("E9CZ9INDbd+2eRQozYqqbQ2yXLVKB9+xcprMF+44U1g=", "sha256");
			// @formatter:off
			http
				.headers()
					.defaultsDisabled()
					.httpPublicKeyPinning()
						.withPins(pins);
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class HpkpConfigCustomAge {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.headers()
					.defaultsDisabled()
					.httpPublicKeyPinning()
						.addSha256Pins("d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM=")
						.maxAgeInSeconds(604800);
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class HpkpConfigTerminateConnection {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.headers()
					.defaultsDisabled()
					.httpPublicKeyPinning()
						.addSha256Pins("d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM=")
						.reportOnly(false);
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class HpkpConfigIncludeSubDomains {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.headers()
					.defaultsDisabled()
					.httpPublicKeyPinning()
						.addSha256Pins("d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM=")
						.includeSubDomains(true);
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class HpkpConfigWithReportURI {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.headers()
					.defaultsDisabled()
					.httpPublicKeyPinning()
						.addSha256Pins("d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM=")
						.reportUri(new URI("https://example.net/pkp-report"));
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class HpkpConfigWithReportURIAsString {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.headers()
					.defaultsDisabled()
					.httpPublicKeyPinning()
						.addSha256Pins("d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM=")
						.reportUri("https://example.net/pkp-report");
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class HpkpWithReportUriInLambdaConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.headers((headers) ->
					headers
						.defaultsDisabled()
						.httpPublicKeyPinning((hpkp) ->
							hpkp
								.addSha256Pins("d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM=")
								.reportUri("https://example.net/pkp-report")
						)
				);
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class ContentSecurityPolicyDefaultConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.headers()
					.defaultsDisabled()
					.contentSecurityPolicy("default-src 'self'");
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class ContentSecurityPolicyReportOnlyConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.headers()
					.defaultsDisabled()
					.contentSecurityPolicy("default-src 'self'; script-src trustedscripts.example.com")
					.reportOnly();
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class ContentSecurityPolicyReportOnlyInLambdaConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.headers((headers) ->
					headers
						.defaultsDisabled()
						.contentSecurityPolicy((csp) ->
							csp
								.policyDirectives("default-src 'self'; script-src trustedscripts.example.com")
								.reportOnly()
						)
				);
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class ContentSecurityPolicyInvalidConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.headers()
					.defaultsDisabled()
					.contentSecurityPolicy("");
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class ContentSecurityPolicyInvalidInLambdaConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.headers((headers) ->
					headers
						.defaultsDisabled()
						.contentSecurityPolicy((csp) ->
								csp.policyDirectives("")
						)
				);
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class ContentSecurityPolicyNoDirectivesInLambdaConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.headers((headers) ->
					headers
						.defaultsDisabled()
						.contentSecurityPolicy(withDefaults())
				);
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class ReferrerPolicyDefaultConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.headers()
					.defaultsDisabled()
					.referrerPolicy();
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class ReferrerPolicyDefaultInLambdaConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.headers((headers) ->
					headers
						.defaultsDisabled()
						.referrerPolicy()
				);
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class ReferrerPolicyCustomConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.headers()
					.defaultsDisabled()
					.referrerPolicy(ReferrerPolicy.SAME_ORIGIN);
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class ReferrerPolicyCustomInLambdaConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.headers((headers) ->
					headers
						.defaultsDisabled()
						.referrerPolicy((referrerPolicy) ->
								referrerPolicy.policy(ReferrerPolicy.SAME_ORIGIN)
						)
				);
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class FeaturePolicyConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.headers()
					.defaultsDisabled()
					.featurePolicy("geolocation 'self'");
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class FeaturePolicyInvalidConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.headers()
					.defaultsDisabled()
					.featurePolicy("");
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class PermissionsPolicyConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.headers()
					.defaultsDisabled()
					.permissionsPolicy((permissionsPolicy) -> permissionsPolicy.policy("geolocation=(self)"));
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class PermissionsPolicyStringConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.headers()
					.defaultsDisabled()
					.permissionsPolicy()
					.policy("geolocation=(self)");
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class PermissionsPolicyInvalidConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.headers()
					.defaultsDisabled()
					.permissionsPolicy((permissionsPolicy) -> permissionsPolicy.policy(null));
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class PermissionsPolicyInvalidStringConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.headers()
					.defaultsDisabled()
					.permissionsPolicy()
					.policy("");
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class HstsWithPreloadConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.headers()
					.defaultsDisabled()
					.httpStrictTransportSecurity()
						.preload(true);
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class HstsWithPreloadInLambdaConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.headers((headers) ->
					headers
						.defaultsDisabled()
						.httpStrictTransportSecurity((hstsConfig) -> hstsConfig.preload(true))
				);
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class CrossOriginCustomPoliciesInLambdaConfig {

		@Bean
		SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http.headers((headers) -> headers
					.defaultsDisabled()
					.crossOriginOpenerPolicy((policy) -> policy
						.policy(CrossOriginOpenerPolicyHeaderWriter.CrossOriginOpenerPolicy.SAME_ORIGIN)
					)
					.crossOriginEmbedderPolicy((policy) -> policy
						.policy(CrossOriginEmbedderPolicyHeaderWriter.CrossOriginEmbedderPolicy.REQUIRE_CORP)
					)
					.crossOriginResourcePolicy((policy) -> policy
						.policy(CrossOriginResourcePolicyHeaderWriter.CrossOriginResourcePolicy.SAME_ORIGIN)
					)
			);
			// @formatter:on
			return http.build();
		}

	}

	@Configuration
	@EnableWebSecurity
	static class CrossOriginCustomPoliciesConfig {

		@Bean
		SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http.headers()
					.defaultsDisabled()
					.crossOriginOpenerPolicy()
						.policy(CrossOriginOpenerPolicyHeaderWriter.CrossOriginOpenerPolicy.SAME_ORIGIN)
						.and()
					.crossOriginEmbedderPolicy()
						.policy(CrossOriginEmbedderPolicyHeaderWriter.CrossOriginEmbedderPolicy.REQUIRE_CORP)
						.and()
					.crossOriginResourcePolicy()
						.policy(CrossOriginResourcePolicyHeaderWriter.CrossOriginResourcePolicy.SAME_ORIGIN);
			// @formatter:on
			return http.build();
		}

	}

}
