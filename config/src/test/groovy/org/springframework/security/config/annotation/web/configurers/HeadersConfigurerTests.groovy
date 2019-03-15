/*
 * Copyright 2002-2016 the original author or authors.
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
package org.springframework.security.config.annotation.web.configurers

import org.springframework.beans.factory.BeanCreationException
import org.springframework.security.config.annotation.BaseSpringSpec
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter

/**
 *
 * @author Rob Winch
 * @author Tim Ysewyn
 * @author Joe Grandja
 */
class HeadersConfigurerTests extends BaseSpringSpec {

	def "headers"() {
		setup:
			loadConfig(HeadersConfig)
			request.secure = true
		when:
			springSecurityFilterChain.doFilter(request,response,chain)
		then:
			responseHeaders == ['X-Content-Type-Options':'nosniff',
						'X-Frame-Options':'DENY',
						'Strict-Transport-Security': 'max-age=31536000 ; includeSubDomains',
						'Cache-Control': 'no-cache, no-store, max-age=0, must-revalidate',
						'Expires' : '0',
						'Pragma':'no-cache',
						'X-XSS-Protection' : '1; mode=block']
	}

	@EnableWebSecurity
	static class HeadersConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http.headers()
		}
	}

	def "headers.contentType"() {
		setup:
			loadConfig(ContentTypeOptionsConfig)
		when:
			springSecurityFilterChain.doFilter(request,response,chain)
		then:
			responseHeaders == ['X-Content-Type-Options':'nosniff']
	}

	@EnableWebSecurity
	static class ContentTypeOptionsConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http
				.headers()
					.defaultsDisabled()
					.contentTypeOptions()
		}
	}

	def "headers.frameOptions"() {
		setup:
			loadConfig(FrameOptionsConfig)
		when:
			springSecurityFilterChain.doFilter(request,response,chain)
		then:
			responseHeaders == ['X-Frame-Options':'DENY']
	}

	@EnableWebSecurity
	static class FrameOptionsConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http
				.headers()
					.defaultsDisabled()
					.frameOptions()
		}
	}

	def "headers.hsts"() {
		setup:
			loadConfig(HstsConfig)
			request.secure = true
		when:
			springSecurityFilterChain.doFilter(request,response,chain)
		then:
			responseHeaders == ['Strict-Transport-Security': 'max-age=31536000 ; includeSubDomains']
	}

	@EnableWebSecurity
	static class HstsConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http
				.headers()
					.defaultsDisabled()
					.httpStrictTransportSecurity()
		}
	}

	def "headers.cacheControl"() {
		setup:
			loadConfig(CacheControlConfig)
		when:
			springSecurityFilterChain.doFilter(request,response,chain)
		then:
			responseHeaders == ['Cache-Control': 'no-cache, no-store, max-age=0, must-revalidate',
						'Expires' : '0',
						'Pragma':'no-cache']
	}

	@EnableWebSecurity
	static class CacheControlConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http
				.headers()
					.defaultsDisabled()
					.cacheControl()
		}
	}

	def "headers.xssProtection"() {
		setup:
			loadConfig(XssProtectionConfig)
		when:
			springSecurityFilterChain.doFilter(request,response,chain)
		then:
			responseHeaders == ['X-XSS-Protection' : '1; mode=block']
	}

	@EnableWebSecurity
	static class XssProtectionConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http
				.headers()
					.defaultsDisabled()
					.xssProtection()
		}
	}

	def "headers custom x-frame-options"() {
		setup:
			loadConfig(HeadersCustomSameOriginConfig)
			request.secure = true
		when:
			springSecurityFilterChain.doFilter(request,response,chain)
		then:
			responseHeaders == ['X-Content-Type-Options':'nosniff',
						'X-Frame-Options':'SAMEORIGIN',
						'Strict-Transport-Security': 'max-age=31536000 ; includeSubDomains',
						'Cache-Control': 'no-cache, no-store, max-age=0, must-revalidate',
						'Expires' : '0',
						'Pragma':'no-cache',
						'X-XSS-Protection' : '1; mode=block']
	}

	@EnableWebSecurity
	static class HeadersCustomSameOriginConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http
				.headers()
					.frameOptions().sameOrigin()
		}
	}

	def "headers.hpkp no pins"() {
		setup:
			loadConfig(HpkpConfigNoPins)
			request.secure = true
		when:
			springSecurityFilterChain.doFilter(request,response,chain)
		then:
			responseHeaders == [:]
	}

	@EnableWebSecurity
	static class HpkpConfigNoPins extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http
					.headers()
					.defaultsDisabled()
					.httpPublicKeyPinning()
		}
	}

	def "headers.hpkp"() {
		setup:
			loadConfig(HpkpConfig)
			request.secure = true
		when:
			springSecurityFilterChain.doFilter(request,response,chain)
		then:
			responseHeaders == ['Public-Key-Pins-Report-Only' : 'max-age=5184000 ; pin-sha256="d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM="']
	}

	def "headers.hpkp no secure request"() {
		setup:
			loadConfig(HpkpConfig)
		when:
			springSecurityFilterChain.doFilter(request,response,chain)
			then:
			responseHeaders == [:]
	}

	@EnableWebSecurity
	static class HpkpConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http
					.headers()
					.defaultsDisabled()
					.httpPublicKeyPinning()
					.addSha256Pins("d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM=")
		}
	}

	def "headers.hpkp with pins"() {
		setup:
			loadConfig(HpkpConfigWithPins)
			request.secure = true
		when:
			springSecurityFilterChain.doFilter(request,response,chain)
		then:
			responseHeaders == ['Public-Key-Pins-Report-Only' : 'max-age=5184000 ; pin-sha256="d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM=" ; pin-sha256="E9CZ9INDbd+2eRQozYqqbQ2yXLVKB9+xcprMF+44U1g="']
	}

	@EnableWebSecurity
	static class HpkpConfigWithPins extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			Map<String, String> pins = new LinkedHashMap<>();
			pins.put("d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM=", "sha256");
			pins.put("E9CZ9INDbd+2eRQozYqqbQ2yXLVKB9+xcprMF+44U1g=", "sha256");

			http
					.headers()
					.defaultsDisabled()
					.httpPublicKeyPinning()
					.withPins(pins)
		}
	}

	def "headers.hpkp custom age"() {
		setup:
			loadConfig(HpkpConfigCustomAge)
			request.secure = true
		when:
			springSecurityFilterChain.doFilter(request,response,chain)
		then:
			responseHeaders == ['Public-Key-Pins-Report-Only' : 'max-age=604800 ; pin-sha256="d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM="']
	}

	@EnableWebSecurity
	static class HpkpConfigCustomAge extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http
					.headers()
					.defaultsDisabled()
					.httpPublicKeyPinning()
					.addSha256Pins("d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM=")
					.maxAgeInSeconds(604800)
		}
	}

	def "headers.hpkp terminate connection"() {
		setup:
			loadConfig(HpkpConfigTerminateConnection)
			request.secure = true
		when:
			springSecurityFilterChain.doFilter(request,response,chain)
		then:
			responseHeaders == ['Public-Key-Pins' : 'max-age=5184000 ; pin-sha256="d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM="']
	}

	@EnableWebSecurity
	static class HpkpConfigTerminateConnection extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http
					.headers()
					.defaultsDisabled()
					.httpPublicKeyPinning()
					.addSha256Pins("d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM=")
					.reportOnly(false)
		}
	}

	def "headers.hpkp include subdomains"() {
		setup:
			loadConfig(HpkpConfigIncludeSubDomains)
			request.secure = true
		when:
			springSecurityFilterChain.doFilter(request,response,chain)
		then:
			responseHeaders == ['Public-Key-Pins-Report-Only' : 'max-age=5184000 ; pin-sha256="d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM=" ; includeSubDomains']
	}

	@EnableWebSecurity
	static class HpkpConfigIncludeSubDomains extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http
					.headers()
					.defaultsDisabled()
					.httpPublicKeyPinning()
					.addSha256Pins("d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM=")
					.includeSubDomains(true)
		}
	}

	def "headers.hpkp with report URI"() {
		setup:
			loadConfig(HpkpConfigWithReportURI)
			request.secure = true
		when:
			springSecurityFilterChain.doFilter(request,response,chain)
		then:
			responseHeaders == ['Public-Key-Pins-Report-Only' : 'max-age=5184000 ; pin-sha256="d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM=" ; report-uri="http://example.net/pkp-report"']
	}

	@EnableWebSecurity
	static class HpkpConfigWithReportURI extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http
					.headers()
					.defaultsDisabled()
					.httpPublicKeyPinning()
					.addSha256Pins("d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM=")
					.reportUri(new URI("http://example.net/pkp-report"))
		}
	}

	def "headers.hpkp with report URI as String"() {
		setup:
			loadConfig(HpkpConfigWithReportURIAsString)
			request.secure = true
		when:
			springSecurityFilterChain.doFilter(request,response,chain)
		then:
			responseHeaders == ['Public-Key-Pins-Report-Only' : 'max-age=5184000 ; pin-sha256="d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM=" ; report-uri="http://example.net/pkp-report"']
	}

	@EnableWebSecurity
	static class HpkpConfigWithReportURIAsString extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http
					.headers()
					.defaultsDisabled()
					.httpPublicKeyPinning()
					.addSha256Pins("d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM=")
					.reportUri("http://example.net/pkp-report")
		}
	}

	def "headers.contentSecurityPolicy default header"() {
		setup:
			loadConfig(ContentSecurityPolicyDefaultConfig)
			request.secure = true
		when:
			springSecurityFilterChain.doFilter(request,response,chain)
		then:
			responseHeaders == ['Content-Security-Policy': 'default-src \'self\'']
	}

	@EnableWebSecurity
	static class ContentSecurityPolicyDefaultConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http
					.headers()
					.defaultsDisabled()
					.contentSecurityPolicy("default-src 'self'");
		}
	}

	def "headers.contentSecurityPolicy report-only header"() {
		setup:
			loadConfig(ContentSecurityPolicyReportOnlyConfig)
			request.secure = true
		when:
			springSecurityFilterChain.doFilter(request,response,chain)
		then:
			responseHeaders == ['Content-Security-Policy-Report-Only': 'default-src \'self\'; script-src trustedscripts.example.com']
	}

	@EnableWebSecurity
	static class ContentSecurityPolicyReportOnlyConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http
					.headers()
					.defaultsDisabled()
					.contentSecurityPolicy("default-src 'self'; script-src trustedscripts.example.com").reportOnly();
		}
	}

	def "headers.contentSecurityPolicy empty policyDirectives"() {
		when:
			loadConfig(ContentSecurityPolicyInvalidConfig)
		then:
			thrown(BeanCreationException)
	}

	@EnableWebSecurity
	static class ContentSecurityPolicyInvalidConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http
					.headers()
					.defaultsDisabled()
					.contentSecurityPolicy("");
		}
	}

}
