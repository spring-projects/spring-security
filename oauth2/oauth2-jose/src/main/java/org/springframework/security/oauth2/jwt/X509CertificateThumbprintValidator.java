/*
 * Copyright 2004-present the original author or authors.
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

package org.springframework.security.oauth2.jwt;

import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Map;
import java.util.function.Supplier;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;

/**
 * An {@link OAuth2TokenValidator} responsible for validating the {@code x5t#S256} claim
 * (if available) in the {@link Jwt} against the SHA-256 Thumbprint of the supplied
 * {@code X509Certificate}.
 *
 * @author Joe Grandja
 * @since 6.3
 * @see OAuth2TokenValidator
 * @see Jwt
 * @see <a target="_blank" href=
 * "https://datatracker.ietf.org/doc/html/rfc8705#section-3">3. Mutual-TLS Client
 * Certificate-Bound Access Tokens</a>
 * @see <a target="_blank" href=
 * "https://datatracker.ietf.org/doc/html/rfc8705#section-3.1">3.1. JWT Certificate
 * Thumbprint Confirmation Method</a>
 */
public class X509CertificateThumbprintValidator implements OAuth2TokenValidator<Jwt> {

	public static final Supplier<X509Certificate> DEFAULT_X509_CERTIFICATE_SUPPLIER = new DefaultX509CertificateSupplier();

	private final Log logger = LogFactory.getLog(getClass());

	private final Supplier<X509Certificate> x509CertificateSupplier;

	public X509CertificateThumbprintValidator(Supplier<X509Certificate> x509CertificateSupplier) {
		Assert.notNull(x509CertificateSupplier, "x509CertificateSupplier cannot be null");
		this.x509CertificateSupplier = x509CertificateSupplier;
	}

	@Override
	public OAuth2TokenValidatorResult validate(Jwt jwt) {
		Map<String, Object> confirmationMethodClaim = jwt.getClaim("cnf");
		String x509CertificateThumbprintClaim = null;
		if (!CollectionUtils.isEmpty(confirmationMethodClaim) && confirmationMethodClaim.containsKey("x5t#S256")) {
			x509CertificateThumbprintClaim = (String) confirmationMethodClaim.get("x5t#S256");
		}
		if (x509CertificateThumbprintClaim == null) {
			return OAuth2TokenValidatorResult.success();
		}

		X509Certificate x509Certificate = this.x509CertificateSupplier.get();
		if (x509Certificate == null) {
			OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.INVALID_TOKEN,
					"Unable to obtain X509Certificate from current request.", null);
			if (this.logger.isDebugEnabled()) {
				this.logger.debug(error.toString());
			}
			return OAuth2TokenValidatorResult.failure(error);
		}

		String x509CertificateThumbprint;
		try {
			x509CertificateThumbprint = computeSHA256Thumbprint(x509Certificate);
		}
		catch (Exception ex) {
			OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.INVALID_TOKEN,
					"Failed to compute SHA-256 Thumbprint for X509Certificate.", null);
			if (this.logger.isDebugEnabled()) {
				this.logger.debug(error.toString());
			}
			return OAuth2TokenValidatorResult.failure(error);
		}

		if (!x509CertificateThumbprint.equals(x509CertificateThumbprintClaim)) {
			OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.INVALID_TOKEN,
					"Invalid SHA-256 Thumbprint for X509Certificate.", null);
			if (this.logger.isDebugEnabled()) {
				this.logger.debug(error.toString());
			}
			return OAuth2TokenValidatorResult.failure(error);
		}

		return OAuth2TokenValidatorResult.success();
	}

	public static String computeSHA256Thumbprint(X509Certificate x509Certificate) throws Exception {
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		byte[] digest = md.digest(x509Certificate.getEncoded());
		return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
	}

	private static final class DefaultX509CertificateSupplier implements Supplier<X509Certificate> {

		@Override
		public X509Certificate get() {
			RequestAttributes requestAttributes = RequestContextHolder.getRequestAttributes();
			if (requestAttributes == null) {
				return null;
			}

			X509Certificate[] clientCertificateChain = (X509Certificate[]) requestAttributes
				.getAttribute("jakarta.servlet.request.X509Certificate", RequestAttributes.SCOPE_REQUEST);

			return (clientCertificateChain != null && clientCertificateChain.length > 0) ? clientCertificateChain[0]
					: null;
		}

	}

}
