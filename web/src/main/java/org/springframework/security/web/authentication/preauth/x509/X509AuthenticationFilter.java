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

package org.springframework.security.web.authentication.preauth.x509;

import java.security.cert.X509Certificate;

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.core.log.LogMessage;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;

/**
 * @author Luke Taylor
 */
public class X509AuthenticationFilter extends AbstractPreAuthenticatedProcessingFilter {

	private X509PrincipalExtractor principalExtractor = new SubjectDnX509PrincipalExtractor();

	@Override
	protected Object getPreAuthenticatedPrincipal(HttpServletRequest request) {
		X509Certificate cert = extractClientCertificate(request);
		return (cert != null) ? this.principalExtractor.extractPrincipal(cert) : null;
	}

	@Override
	protected Object getPreAuthenticatedCredentials(HttpServletRequest request) {
		return extractClientCertificate(request);
	}

	private X509Certificate extractClientCertificate(HttpServletRequest request) {
		X509Certificate[] certs = (X509Certificate[]) request.getAttribute("jakarta.servlet.request.X509Certificate");
		if (certs != null && certs.length > 0) {
			this.logger.debug(LogMessage.format("X.509 client authentication certificate:%s", certs[0]));
			return certs[0];
		}
		this.logger.debug("No client certificate found in request.");
		return null;
	}

	public void setPrincipalExtractor(X509PrincipalExtractor principalExtractor) {
		this.principalExtractor = principalExtractor;
	}

}
