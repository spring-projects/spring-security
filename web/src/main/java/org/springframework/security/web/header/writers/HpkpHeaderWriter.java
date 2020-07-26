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
package org.springframework.security.web.header.writers;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.LinkedHashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.security.web.header.HeaderWriter;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;

/**
 * Provides support for <a href="https://tools.ietf.org/html/rfc7469">HTTP Public Key
 * Pinning (HPKP)</a>.
 *
 * <p>
 * Since <a href="https://tools.ietf.org/html/rfc7469#section-4.1">Section 4.1</a> states
 * that a value on the order of 60 days (5,184,000 seconds) may be considered a good
 * balance, we use this value as the default. This can be customized using
 * {@link #setMaxAgeInSeconds(long)}.
 * </p>
 *
 * <p>
 * Because <a href="https://tools.ietf.org/html/rfc7469#appendix-B">Appendix B</a>
 * recommends that operators should first deploy public key pinning by using the
 * report-only mode, we opted to use this mode as default. This can be customized using
 * {@link #setReportOnly(boolean)}.
 * </p>
 *
 * <p>
 * Since we need to validate a certificate chain, the "Public-Key-Pins" or
 * "Public-Key-Pins-Report-Only" header will only be added when
 * {@link HttpServletRequest#isSecure()} returns {@code true}.
 * </p>
 *
 * <p>
 * To set the pins you first need to extract the public key information from your
 * certificate or key file and encode them using Base64. The following commands will help
 * you extract the Base64 encoded information from a key file, a certificate signing
 * request, or a certificate.
 *
 * <pre>
 * openssl rsa -in my-key-file.key -outform der -pubout | openssl dgst -sha256 -binary | openssl enc -base64
 *
 * openssl req -in my-signing-request.csr -pubkey -noout | openssl rsa -pubin -outform der | openssl dgst -sha256 -binary | openssl enc -base64
 *
 * openssl x509 -in my-certificate.crt -pubkey -noout | openssl rsa -pubin -outform der | openssl dgst -sha256 -binary | openssl enc -base64
 * </pre>
 *
 *
 * The following command will extract the Base64 encoded information for a website.
 *
 * <pre>
 * openssl s_client -servername www.example.com -connect www.example.com:443 | openssl x509 -pubkey -noout | openssl rsa -pubin -outform der | openssl dgst -sha256 -binary | openssl enc -base64
 * </pre>
 * </p>
 *
 * <p>
 * Some examples:
 *
 * <pre>
 * Public-Key-Pins: max-age=3000;
 * 		pin-sha256="d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM=";
 * 		pin-sha256="E9CZ9INDbd+2eRQozYqqbQ2yXLVKB9+xcprMF+44U1g="
 *
 * Public-Key-Pins: max-age=5184000;
 * 		pin-sha256="E9CZ9INDbd+2eRQozYqqbQ2yXLVKB9+xcprMF+44U1g=";
 * 		pin-sha256="LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ="
 *
 * Public-Key-Pins: max-age=5184000;
 * 		pin-sha256="E9CZ9INDbd+2eRQozYqqbQ2yXLVKB9+xcprMF+44U1g=";
 * 		pin-sha256="LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ=";
 * 		report-uri="https://example.com/pkp-report"
 *
 * Public-Key-Pins-Report-Only: max-age=5184000;
 * 		pin-sha256="E9CZ9INDbd+2eRQozYqqbQ2yXLVKB9+xcprMF+44U1g=";
 * 		pin-sha256="LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ=";
 * 		report-uri="https://other.example.net/pkp-report"
 *
 * Public-Key-Pins: max-age=5184000;
 * 		pin-sha256="d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM=";
 * 		pin-sha256="E9CZ9INDbd+2eRQozYqqbQ2yXLVKB9+xcprMF+44U1g=";
 * 		pin-sha256="LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ=";
 * 		includeSubDomains
 * </pre>
 * </p>
 *
 * @author Tim Ysewyn
 * @author Ankur Pathak
 * @since 4.1
 */
public final class HpkpHeaderWriter implements HeaderWriter {

	private static final long DEFAULT_MAX_AGE_SECONDS = 5184000;

	private static final String HPKP_HEADER_NAME = "Public-Key-Pins";

	private static final String HPKP_RO_HEADER_NAME = "Public-Key-Pins-Report-Only";

	private final Log logger = LogFactory.getLog(getClass());

	private final RequestMatcher requestMatcher = new SecureRequestMatcher();

	private Map<String, String> pins = new LinkedHashMap<>();

	private long maxAgeInSeconds;

	private boolean includeSubDomains;

	private boolean reportOnly;

	private URI reportUri;

	private String hpkpHeaderValue;

	/**
	 * Creates a new instance
	 * @param maxAgeInSeconds maps to {@link #setMaxAgeInSeconds(long)}
	 * @param includeSubDomains maps to {@link #setIncludeSubDomains(boolean)}
	 * @param reportOnly maps to {@link #setReportOnly(boolean)}
	 */
	public HpkpHeaderWriter(long maxAgeInSeconds, boolean includeSubDomains, boolean reportOnly) {
		this.maxAgeInSeconds = maxAgeInSeconds;
		this.includeSubDomains = includeSubDomains;
		this.reportOnly = reportOnly;
		updateHpkpHeaderValue();
	}

	/**
	 * Creates a new instance
	 * @param maxAgeInSeconds maps to {@link #setMaxAgeInSeconds(long)}
	 * @param includeSubDomains maps to {@link #setIncludeSubDomains(boolean)}
	 */
	public HpkpHeaderWriter(long maxAgeInSeconds, boolean includeSubDomains) {
		this(maxAgeInSeconds, includeSubDomains, true);
	}

	/**
	 * Creates a new instance
	 * @param maxAgeInSeconds maps to {@link #setMaxAgeInSeconds(long)}
	 */
	public HpkpHeaderWriter(long maxAgeInSeconds) {
		this(maxAgeInSeconds, false);
	}

	/**
	 * Creates a new instance
	 */
	public HpkpHeaderWriter() {
		this(DEFAULT_MAX_AGE_SECONDS);
	}

	/*
	 * (non-Javadoc)
	 *
	 * @see org.springframework.security.web.headers.HeaderWriter#writeHeaders(javax
	 * .servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse)
	 */
	@Override
	public void writeHeaders(HttpServletRequest request, HttpServletResponse response) {
		if (this.requestMatcher.matches(request)) {
			if (!this.pins.isEmpty()) {
				String headerName = this.reportOnly ? HPKP_RO_HEADER_NAME : HPKP_HEADER_NAME;
				if (!response.containsHeader(headerName)) {
					response.setHeader(headerName, this.hpkpHeaderValue);
				}
			}
			if (this.logger.isDebugEnabled()) {
				this.logger.debug("Not injecting HPKP header since there aren't any pins");
			}
		}
		else if (this.logger.isDebugEnabled()) {
			this.logger.debug("Not injecting HPKP header since it wasn't a secure connection");
		}
	}

	/**
	 * <p>
	 * Sets the value for the pin- directive of the Public-Key-Pins header.
	 * </p>
	 *
	 * <p>
	 * The pin directive specifies a way for web host operators to indicate a
	 * cryptographic identity that should be bound to a given web host. See
	 * <a href="https://tools.ietf.org/html/rfc7469#section-2.1.1">Section 2.1.1</a> for
	 * additional details.
	 * </p>
	 *
	 * <p>
	 * To get a pin of
	 *
	 * Public-Key-Pins: pin-sha256="d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM=";
	 * pin-sha256="E9CZ9INDbd+2eRQozYqqbQ2yXLVKB9+xcprMF+44U1g="
	 *
	 * Use
	 *
	 * <code>
	 * Map&lt;String, String&gt; pins = new HashMap&lt;String, String&gt;();
	 * pins.put("d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM=", "sha256");
	 * pins.put("E9CZ9INDbd+2eRQozYqqbQ2yXLVKB9+xcprMF+44U1g=", "sha256");
	 * </code>
	 * </p>
	 * @param pins the map of base64-encoded SPKI fingerprint &amp; cryptographic hash
	 * algorithm pairs.
	 * @throws IllegalArgumentException if pins is null
	 */
	public void setPins(Map<String, String> pins) {
		Assert.notNull(pins, "pins cannot be null");
		this.pins = pins;
		updateHpkpHeaderValue();
	}

	/**
	 * <p>
	 * Adds a list of SHA256 hashed pins for the pin- directive of the Public-Key-Pins
	 * header.
	 * </p>
	 *
	 * <p>
	 * The pin directive specifies a way for web host operators to indicate a
	 * cryptographic identity that should be bound to a given web host. See
	 * <a href="https://tools.ietf.org/html/rfc7469#section-2.1.1">Section 2.1.1</a> for
	 * additional details.
	 * </p>
	 *
	 * <p>
	 * To get a pin of
	 *
	 * Public-Key-Pins-Report-Only:
	 * pin-sha256="d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM=";
	 * pin-sha256="E9CZ9INDbd+2eRQozYqqbQ2yXLVKB9+xcprMF+44U1g="
	 *
	 * Use
	 *
	 * HpkpHeaderWriter hpkpHeaderWriter = new HpkpHeaderWriter();
	 * hpkpHeaderWriter.addSha256Pins("d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM",
	 * "E9CZ9INDbd+2eRQozYqqbQ2yXLVKB9+xcprMF+44U1g=");
	 * </p>
	 * @param pins a list of base64-encoded SPKI fingerprints.
	 * @throws IllegalArgumentException if a pin is null
	 */
	public void addSha256Pins(String... pins) {
		for (String pin : pins) {
			Assert.notNull(pin, "pin cannot be null");
			this.pins.put(pin, "sha256");
		}
		updateHpkpHeaderValue();
	}

	/**
	 * <p>
	 * Sets the value (in seconds) for the max-age directive of the Public-Key-Pins
	 * header. The default is 60 days.
	 * </p>
	 *
	 * <p>
	 * This instructs browsers how long they should regard the host (from whom the message
	 * was received) as a known pinned host. See
	 * <a href="https://tools.ietf.org/html/rfc7469#section-2.1.2">Section 2.1.2</a> for
	 * additional details.
	 * </p>
	 *
	 * <p>
	 * To get a header like
	 *
	 * Public-Key-Pins-Report-Only: max-age=2592000;
	 * pin-sha256="d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM=";
	 * pin-sha256="E9CZ9INDbd+2eRQozYqqbQ2yXLVKB9+xcprMF+44U1g="
	 *
	 * Use
	 *
	 * HpkpHeaderWriter hpkpHeaderWriter = new HpkpHeaderWriter();
	 * hpkpHeaderWriter.setMaxAgeInSeconds(TimeUnit.DAYS.toSeconds(30));
	 * </p>
	 * @param maxAgeInSeconds the maximum amount of time (in seconds) to regard the host
	 * as a known pinned host. (i.e. TimeUnit.DAYS.toSeconds(30) would set this to 30
	 * days)
	 * @throws IllegalArgumentException if maxAgeInSeconds is negative
	 */
	public void setMaxAgeInSeconds(long maxAgeInSeconds) {
		if (maxAgeInSeconds < 0) {
			throw new IllegalArgumentException("maxAgeInSeconds must be non-negative. Got " + maxAgeInSeconds);
		}
		this.maxAgeInSeconds = maxAgeInSeconds;
		updateHpkpHeaderValue();
	}

	/**
	 * <p>
	 * If true, the pinning policy applies to this pinned host as well as any subdomains
	 * of the host's domain name. The default is false.
	 * </p>
	 *
	 * <p>
	 * See <a href="https://tools.ietf.org/html/rfc7469#section-2.1.3">Section 2.1.3</a>
	 * for additional details.
	 * </p>
	 *
	 * <p>
	 * To get a header like
	 *
	 * Public-Key-Pins-Report-Only: max-age=5184000;
	 * pin-sha256="d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM=";
	 * pin-sha256="E9CZ9INDbd+2eRQozYqqbQ2yXLVKB9+xcprMF+44U1g="; includeSubDomains
	 *
	 * you should set this to true.
	 * </p>
	 * @param includeSubDomains true to include subdomains, else false
	 */
	public void setIncludeSubDomains(boolean includeSubDomains) {
		this.includeSubDomains = includeSubDomains;
		updateHpkpHeaderValue();
	}

	/**
	 * <p>
	 * To get a Public-Key-Pins header you should set this to false, otherwise the header
	 * will be Public-Key-Pins-Report-Only. When in report-only mode, the browser should
	 * not terminate the connection with the server. By default this is true.
	 * </p>
	 *
	 * <p>
	 * See <a href="https://tools.ietf.org/html/rfc7469#section-2.1">Section 2.1</a> for
	 * additional details.
	 * </p>
	 *
	 * <p>
	 * To get a header like
	 *
	 * Public-Key-Pins: max-age=5184000;
	 * pin-sha256="d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM=";
	 * pin-sha256="E9CZ9INDbd+2eRQozYqqbQ2yXLVKB9+xcprMF+44U1g="
	 *
	 * you should the this to false.
	 * </p>
	 * @param reportOnly true to report only, else false
	 */
	public void setReportOnly(boolean reportOnly) {
		this.reportOnly = reportOnly;
	}

	/**
	 * <p>
	 * Sets the URI to which the browser should report pin validation failures.
	 * </p>
	 *
	 * <p>
	 * See <a href="https://tools.ietf.org/html/rfc7469#section-2.1.4">Section 2.1.4</a>
	 * for additional details.
	 * </p>
	 *
	 * <p>
	 * To get a header like
	 *
	 * Public-Key-Pins-Report-Only: max-age=5184000;
	 * pin-sha256="E9CZ9INDbd+2eRQozYqqbQ2yXLVKB9+xcprMF+44U1g=";
	 * pin-sha256="LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ=";
	 * report-uri="https://other.example.net/pkp-report"
	 *
	 * Use
	 *
	 * HpkpHeaderWriter hpkpHeaderWriter = new HpkpHeaderWriter();
	 * hpkpHeaderWriter.setReportUri(new URI("https://other.example.net/pkp-report"));
	 * </p>
	 * @param reportUri the URI where the browser should send the report to.
	 */
	public void setReportUri(URI reportUri) {
		this.reportUri = reportUri;
		updateHpkpHeaderValue();
	}

	/**
	 * <p>
	 * Sets the URI to which the browser should report pin validation failures.
	 * </p>
	 *
	 * <p>
	 * See <a href="https://tools.ietf.org/html/rfc7469#section-2.1.4">Section 2.1.4</a>
	 * for additional details.
	 * </p>
	 *
	 * <p>
	 * To get a header like
	 *
	 * Public-Key-Pins-Report-Only: max-age=5184000;
	 * pin-sha256="E9CZ9INDbd+2eRQozYqqbQ2yXLVKB9+xcprMF+44U1g=";
	 * pin-sha256="LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ=";
	 * report-uri="https://other.example.net/pkp-report"
	 *
	 * Use
	 *
	 * HpkpHeaderWriter hpkpHeaderWriter = new HpkpHeaderWriter();
	 * hpkpHeaderWriter.setReportUri("https://other.example.net/pkp-report");
	 * </p>
	 * @param reportUri the URI where the browser should send the report to.
	 * @throws IllegalArgumentException if the reportUri is not a valid URI
	 */
	public void setReportUri(String reportUri) {
		try {
			this.reportUri = new URI(reportUri);
		}
		catch (URISyntaxException e) {
			throw new IllegalArgumentException(e);
		}
		updateHpkpHeaderValue();
	}

	private void updateHpkpHeaderValue() {
		String headerValue = "max-age=" + this.maxAgeInSeconds;
		for (Map.Entry<String, String> pin : this.pins.entrySet()) {
			headerValue += " ; pin-" + pin.getValue() + "=\"" + pin.getKey() + "\"";
		}
		if (this.reportUri != null) {
			headerValue += " ; report-uri=\"" + this.reportUri.toString() + "\"";
		}
		if (this.includeSubDomains) {
			headerValue += " ; includeSubDomains";
		}
		this.hpkpHeaderValue = headerValue;
	}

	private static final class SecureRequestMatcher implements RequestMatcher {

		@Override
		public boolean matches(HttpServletRequest request) {
			return request.isSecure();
		}

	}

}
