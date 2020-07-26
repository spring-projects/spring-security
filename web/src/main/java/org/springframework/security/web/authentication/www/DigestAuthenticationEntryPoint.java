/*
 * Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
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

package org.springframework.security.web.authentication.www;

import java.io.IOException;
import java.util.Base64;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.core.Ordered;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

/**
 * Used by the <code>SecurityEnforcementFilter</code> to commence authentication via the
 * {@link DigestAuthenticationFilter}.
 * <p>
 * The nonce sent back to the user agent will be valid for the period indicated by
 * {@link #setNonceValiditySeconds(int)}. By default this is 300 seconds. Shorter times
 * should be used if replay attacks are a major concern. Larger values can be used if
 * performance is a greater concern. This class correctly presents the
 * <code>stale=true</code> header when the nonce has expired, so properly implemented user
 * agents will automatically renegotiate with a new nonce value (i.e. without presenting a
 * new password dialog box to the user).
 *
 * @author Ben Alex
 */
public class DigestAuthenticationEntryPoint implements AuthenticationEntryPoint, InitializingBean, Ordered {

	private static final Log logger = LogFactory.getLog(DigestAuthenticationEntryPoint.class);

	private String key;

	private String realmName;

	private int nonceValiditySeconds = 300;

	private int order = Integer.MAX_VALUE; // ~ default

	public int getOrder() {
		return this.order;
	}

	public void setOrder(int order) {
		this.order = order;
	}

	public void afterPropertiesSet() {
		if ((this.realmName == null) || "".equals(this.realmName)) {
			throw new IllegalArgumentException("realmName must be specified");
		}

		if ((this.key == null) || "".equals(this.key)) {
			throw new IllegalArgumentException("key must be specified");
		}
	}

	public void commence(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException authException) throws IOException {
		HttpServletResponse httpResponse = response;

		// compute a nonce (do not use remote IP address due to proxy farms)
		// format of nonce is:
		// base64(expirationTime + ":" + md5Hex(expirationTime + ":" + key))
		long expiryTime = System.currentTimeMillis() + (this.nonceValiditySeconds * 1000);
		String signatureValue = DigestAuthUtils.md5Hex(expiryTime + ":" + this.key);
		String nonceValue = expiryTime + ":" + signatureValue;
		String nonceValueBase64 = new String(Base64.getEncoder().encode(nonceValue.getBytes()));

		// qop is quality of protection, as defined by RFC 2617.
		// we do not use opaque due to IE violation of RFC 2617 in not
		// representing opaque on subsequent requests in same session.
		String authenticateHeader = "Digest realm=\"" + this.realmName + "\", " + "qop=\"auth\", nonce=\""
				+ nonceValueBase64 + "\"";

		if (authException instanceof NonceExpiredException) {
			authenticateHeader = authenticateHeader + ", stale=\"true\"";
		}

		if (logger.isDebugEnabled()) {
			logger.debug("WWW-Authenticate header sent to user agent: " + authenticateHeader);
		}

		httpResponse.addHeader("WWW-Authenticate", authenticateHeader);
		httpResponse.sendError(HttpStatus.UNAUTHORIZED.value(), HttpStatus.UNAUTHORIZED.getReasonPhrase());
	}

	public String getKey() {
		return this.key;
	}

	public int getNonceValiditySeconds() {
		return this.nonceValiditySeconds;
	}

	public String getRealmName() {
		return this.realmName;
	}

	public void setKey(String key) {
		this.key = key;
	}

	public void setNonceValiditySeconds(int nonceValiditySeconds) {
		this.nonceValiditySeconds = nonceValiditySeconds;
	}

	public void setRealmName(String realmName) {
		this.realmName = realmName;
	}

}
