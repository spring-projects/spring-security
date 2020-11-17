/*
 * Copyright 2002-2021 the original author or authors.
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

package org.springframework.security.oauth2.client.endpoint;

import java.net.URL;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.util.Base64URL;

import org.springframework.core.convert.converter.Converter;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

/*
 * NOTE:
 * This originated in gh-9208 (JwtEncoder),
 * which is required to realize the feature in gh-8175 (JWT Client Authentication).
 * However, we decided not to merge gh-9208 as part of the 5.5.0 release
 * and instead packaged it up privately with the gh-8175 feature.
 * We MAY merge gh-9208 in a later release but that is yet to be determined.
 *
 * gh-9208 Introduce JwtEncoder
 * https://github.com/spring-projects/spring-security/pull/9208
 *
 * gh-8175 Support JWT for Client Authentication
 * https://github.com/spring-projects/spring-security/issues/8175
 */

/**
 * A {@link Converter} that converts a {@link JoseHeader} to
 * {@code com.nimbusds.jose.JWSHeader}.
 *
 * @author Joe Grandja
 * @since 5.5
 * @see Converter
 * @see JoseHeader
 * @see com.nimbusds.jose.JWSHeader
 */
final class JwsHeaderConverter implements Converter<JoseHeader, JWSHeader> {

	@Override
	public JWSHeader convert(JoseHeader headers) {
		JWSHeader.Builder builder = new JWSHeader.Builder(JWSAlgorithm.parse(headers.getAlgorithm().getName()));

		URL jwkSetUri = headers.getJwkSetUri();
		if (jwkSetUri != null) {
			try {
				builder.jwkURL(jwkSetUri.toURI());
			}
			catch (Exception ex) {
				throw new IllegalArgumentException(
						"Unable to convert '" + JoseHeaderNames.JKU + "' JOSE header to a URI", ex);
			}
		}

		Map<String, Object> jwk = headers.getJwk();
		if (!CollectionUtils.isEmpty(jwk)) {
			try {
				builder.jwk(JWK.parse(jwk));
			}
			catch (Exception ex) {
				throw new IllegalArgumentException("Unable to convert '" + JoseHeaderNames.JWK + "' JOSE header", ex);
			}
		}

		String keyId = headers.getKeyId();
		if (StringUtils.hasText(keyId)) {
			builder.keyID(keyId);
		}

		URL x509Uri = headers.getX509Uri();
		if (x509Uri != null) {
			try {
				builder.x509CertURL(x509Uri.toURI());
			}
			catch (Exception ex) {
				throw new IllegalArgumentException(
						"Unable to convert '" + JoseHeaderNames.X5U + "' JOSE header to a URI", ex);
			}
		}

		List<String> x509CertificateChain = headers.getX509CertificateChain();
		if (!CollectionUtils.isEmpty(x509CertificateChain)) {
			builder.x509CertChain(x509CertificateChain.stream().map(Base64::new).collect(Collectors.toList()));
		}

		String x509SHA1Thumbprint = headers.getX509SHA1Thumbprint();
		if (StringUtils.hasText(x509SHA1Thumbprint)) {
			builder.x509CertThumbprint(new Base64URL(x509SHA1Thumbprint));
		}

		String x509SHA256Thumbprint = headers.getX509SHA256Thumbprint();
		if (StringUtils.hasText(x509SHA256Thumbprint)) {
			builder.x509CertSHA256Thumbprint(new Base64URL(x509SHA256Thumbprint));
		}

		String type = headers.getType();
		if (StringUtils.hasText(type)) {
			builder.type(new JOSEObjectType(type));
		}

		String contentType = headers.getContentType();
		if (StringUtils.hasText(contentType)) {
			builder.contentType(contentType);
		}

		Set<String> critical = headers.getCritical();
		if (!CollectionUtils.isEmpty(critical)) {
			builder.criticalParams(critical);
		}

		Map<String, Object> customHeaders = headers.getHeaders().entrySet().stream()
				.filter((header) -> !JWSHeader.getRegisteredParameterNames().contains(header.getKey()))
				.collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
		if (!CollectionUtils.isEmpty(customHeaders)) {
			builder.customParams(customHeaders);
		}

		return builder.build();
	}

}
