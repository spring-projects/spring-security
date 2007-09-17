/* Copyright 2004-2007 Acegi Technology Pty Limited
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

package org.acegisecurity.ui.ntlm;

import org.acegisecurity.AuthenticationCredentialsNotFoundException;
import org.acegisecurity.AuthenticationException;
import org.acegisecurity.InsufficientAuthenticationException;
import org.acegisecurity.ui.AuthenticationEntryPoint;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.util.Assert;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import jcifs.Config;

/**
 * Used by <code>ExceptionTranslationFilter</code> to assist with the NTLM
 * negotiation.  Also handles redirecting the user to the authentication
 * failure URL if an {@link AuthenticationException} that is not a subclass of
 * {@link NtlmBaseException} is received.
 *
 * @author Davide Baroncelli
 * @author Edward Smith
 * @version $Id$
 */
public class NtlmProcessingFilterEntryPoint implements AuthenticationEntryPoint, InitializingBean {
    //~ Static fields/initializers =============================================

    private static final Log logger = LogFactory.getLog(NtlmProcessingFilterEntryPoint.class);

	//~ Instance fields ================================================================================================

	/** Where to redirect the browser to if authentication fails		*/
	private String authenticationFailureUrl;

	//~ Methods ================================================================

	/**
	 * Ensures an authentication failure URL has been provided in the bean
	 * configuration file.
	 */
	public void afterPropertiesSet() throws Exception {
		Assert.hasLength(authenticationFailureUrl, "authenticationFailureUrl must be specified");
	}

	/**
	 * Sets the authentication failure URL.
	 * 
	 * @param authenticationFailureUrl the authentication failure URL.
	 */
	public void setAuthenticationFailureUrl(String authenticationFailureUrl) {
		this.authenticationFailureUrl = authenticationFailureUrl;
	}

	/**
	 * Sends an NTLM challenge to the browser requiring authentication. The
	 * WWW-Authenticate header is populated with the appropriate information
	 * during the negotiation lifecycle by calling the getMessage() method
	 * from an NTLM-specific subclass of {@link NtlmBaseException}:
	 * <p>
	 * <ul>
	 * <li>{@link NtlmBeginHandshakeException}: NTLM
	 * <li>{@link NtlmType2MessageException}: NTLM &lt;base64-encoded type-2-message&gt;
	 * </ul>
	 * 
	 * If the {@link AuthenticationException} is not a subclass of
	 * {@link NtlmBaseException}, then redirect the user to the authentication
	 * failure URL.
	 * 
	 * @param request The {@link HttpServletRequest} object.
	 * @param response Then {@link HttpServletResponse} object.
	 * @param authException Either {@link NtlmBeginHandshakeException},
	 * 						{@link NtlmType2MessageException}, or
	 * 						{@link AuthenticationException}
	 */
	public void commence(final ServletRequest request, final ServletResponse response, final AuthenticationException authException) throws IOException, ServletException {
		final HttpServletResponse resp = (HttpServletResponse) response;

		if (authException instanceof NtlmBaseException) {
			if (authException instanceof NtlmType2MessageException) {
				((NtlmType2MessageException) authException).preserveAuthentication();
			}
			resp.setHeader("WWW-Authenticate", authException.getMessage());
			resp.setHeader("Connection", "Keep-Alive");
			resp.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
			resp.setContentLength(0);
			resp.flushBuffer();
		} else {
			String url = authenticationFailureUrl;
			if (!url.startsWith("http://") && !url.startsWith("https://")) {
				url = ((HttpServletRequest) request).getContextPath() + url;
			}

			resp.sendRedirect(resp.encodeRedirectURL(url));
		}
	}

}	// End NtlmProcessingFilterEntryPoint
