/*
 * Copyright 2002-2018 the original author or authors.
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

package org.springframework.security.web.server.authentication;

import java.security.cert.X509Certificate;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import reactor.core.publisher.Mono;

import org.springframework.http.server.reactive.SslInfo;
import org.springframework.lang.NonNull;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.security.web.authentication.preauth.x509.X509PrincipalExtractor;
import org.springframework.web.server.ServerWebExchange;

/**
 * Converts from a {@link SslInfo} provided by a request to an
 * {@link PreAuthenticatedAuthenticationToken} that can be authenticated.
 *
 * @author Alexey Nesterov
 * @since 5.2
 */
public class ServerX509AuthenticationConverter implements ServerAuthenticationConverter {

	protected final Log logger = LogFactory.getLog(getClass());

	private final X509PrincipalExtractor principalExtractor;

	public ServerX509AuthenticationConverter(@NonNull X509PrincipalExtractor principalExtractor) {
		this.principalExtractor = principalExtractor;
	}

	@Override
	public Mono<Authentication> convert(ServerWebExchange exchange) {
		SslInfo sslInfo = exchange.getRequest().getSslInfo();
		if (sslInfo == null) {
			if (this.logger.isDebugEnabled()) {
				this.logger.debug("No SslInfo provided with a request, skipping x509 authentication");
			}

			return Mono.empty();
		}

		if (sslInfo.getPeerCertificates() == null || sslInfo.getPeerCertificates().length == 0) {
			if (this.logger.isDebugEnabled()) {
				this.logger.debug("No peer certificates found in SslInfo, skipping x509 authentication");
			}

			return Mono.empty();
		}

		X509Certificate clientCertificate = sslInfo.getPeerCertificates()[0];
		Object principal = this.principalExtractor.extractPrincipal(clientCertificate);

		PreAuthenticatedAuthenticationToken authRequest = new PreAuthenticatedAuthenticationToken(principal,
				clientCertificate);

		return Mono.just(authRequest);
	}

}
