/* Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.ui.digestauth;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.AuthenticationException;
import org.springframework.security.ui.AuthenticationEntryPoint;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.core.Ordered;


/**
 * Used by the <code>SecurityEnforcementFilter</code> to commence authentication via the {@link
 * DigestProcessingFilter}.<p>The nonce sent back to the user agent will be valid for the period indicated by
 * {@link #setNonceValiditySeconds(int)}. By default this is 300 seconds. Shorter times should be used if replay
 * attacks are a major concern. Larger values can be used if performance is a greater concern. This class correctly
 * presents the <code>stale=true</code> header when the nonce has expierd, so properly implemented user agents will
 * automatically renegotiate with a new nonce value (ie without presenting a new password dialog box to the user).</p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public class DigestProcessingFilterEntryPoint implements AuthenticationEntryPoint, InitializingBean, Ordered {
    //~ Static fields/initializers =====================================================================================

    private static final Log logger = LogFactory.getLog(DigestProcessingFilterEntryPoint.class);

    //~ Instance fields ================================================================================================

    private String key;
    private String realmName;
    private int nonceValiditySeconds = 300;
    private int order = Integer.MAX_VALUE; // ~ default

    //~ Methods ========================================================================================================

    public int getOrder() {
		return order;
	}

	public void setOrder(int order) {
		this.order = order;
	}

	public void afterPropertiesSet() throws Exception {
        if ((realmName == null) || "".equals(realmName)) {
            throw new IllegalArgumentException("realmName must be specified");
        }

        if ((key == null) || "".equals(key)) {
            throw new IllegalArgumentException("key must be specified");
        }
    }

    public void commence(ServletRequest request, ServletResponse response, AuthenticationException authException)
        throws IOException, ServletException {
        HttpServletResponse httpResponse = (HttpServletResponse) response;

        // compute a nonce (do not use remote IP address due to proxy farms)
        // format of nonce is:
        //   base64(expirationTime + ":" + md5Hex(expirationTime + ":" + key))
        long expiryTime = System.currentTimeMillis() + (nonceValiditySeconds * 1000);
        String signatureValue = new String(DigestUtils.md5Hex(expiryTime + ":" + key));
        String nonceValue = expiryTime + ":" + signatureValue;
        String nonceValueBase64 = new String(Base64.encodeBase64(nonceValue.getBytes()));

        // qop is quality of protection, as defined by RFC 2617.
        // we do not use opaque due to IE violation of RFC 2617 in not
        // representing opaque on subsequent requests in same session.
        String authenticateHeader = "Digest realm=\"" + realmName + "\", " + "qop=\"auth\", nonce=\""
            + nonceValueBase64 + "\"";

        if (authException instanceof NonceExpiredException) {
            authenticateHeader = authenticateHeader + ", stale=\"true\"";
        }

        if (logger.isDebugEnabled()) {
            logger.debug("WWW-Authenticate header sent to user agent: " + authenticateHeader);
        }

        httpResponse.addHeader("WWW-Authenticate", authenticateHeader);
        httpResponse.sendError(HttpServletResponse.SC_UNAUTHORIZED, authException.getMessage());
    }

    public String getKey() {
        return key;
    }

    public int getNonceValiditySeconds() {
        return nonceValiditySeconds;
    }

    public String getRealmName() {
        return realmName;
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
