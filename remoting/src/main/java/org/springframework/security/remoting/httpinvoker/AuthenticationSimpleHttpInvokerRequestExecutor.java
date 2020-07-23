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

package org.springframework.security.remoting.httpinvoker;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.util.Base64;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.remoting.httpinvoker.SimpleHttpInvokerRequestExecutor;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * Adds BASIC authentication support to <code>SimpleHttpInvokerRequestExecutor</code>.
 *
 * @author Ben Alex
 * @author Rob Winch
 */
public class AuthenticationSimpleHttpInvokerRequestExecutor extends SimpleHttpInvokerRequestExecutor {

	private static final Log logger = LogFactory.getLog(AuthenticationSimpleHttpInvokerRequestExecutor.class);

	private AuthenticationTrustResolver trustResolver = new AuthenticationTrustResolverImpl();

	/**
	 * Provided so subclasses can perform additional configuration if required (eg set
	 * additional request headers for non-security related information etc).
	 * @param con the HTTP connection to prepare
	 * @param contentLength the length of the content to send
	 *
	 */
	protected void doPrepareConnection(HttpURLConnection con, int contentLength) throws IOException {
	}

	/**
	 * Called every time a HTTP invocation is made.
	 * <p>
	 * Simply allows the parent to setup the connection, and then adds an
	 * <code>Authorization</code> HTTP header property that will be used for BASIC
	 * authentication.
	 * </p>
	 * <p>
	 * The <code>SecurityContextHolder</code> is used to obtain the relevant principal and
	 * credentials.
	 * </p>
	 * @param con the HTTP connection to prepare
	 * @param contentLength the length of the content to send
	 * @throws IOException if thrown by HttpURLConnection methods
	 */
	protected void prepareConnection(HttpURLConnection con, int contentLength) throws IOException {
		super.prepareConnection(con, contentLength);

		Authentication auth = SecurityContextHolder.getContext().getAuthentication();

		if ((auth != null) && (auth.getName() != null) && (auth.getCredentials() != null)
				&& !trustResolver.isAnonymous(auth)) {
			String base64 = auth.getName() + ":" + auth.getCredentials().toString();
			con.setRequestProperty("Authorization",
					"Basic " + new String(Base64.getEncoder().encode(base64.getBytes())));

			if (logger.isDebugEnabled()) {
				logger.debug("HttpInvocation now presenting via BASIC authentication SecurityContextHolder-derived: "
						+ auth.toString());
			}
		}
		else {
			if (logger.isDebugEnabled()) {
				logger.debug("Unable to set BASIC authentication header as SecurityContext did not provide "
						+ "valid Authentication: " + auth);
			}
		}

		doPrepareConnection(con, contentLength);
	}

}
