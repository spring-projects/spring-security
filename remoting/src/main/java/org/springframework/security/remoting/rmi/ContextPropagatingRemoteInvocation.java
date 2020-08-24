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

package org.springframework.security.remoting.rmi;

import java.lang.reflect.InvocationTargetException;

import org.aopalliance.intercept.MethodInvocation;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.core.log.LogMessage;
import org.springframework.remoting.support.RemoteInvocation;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.SpringSecurityCoreVersion;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * The actual {@code RemoteInvocation} that is passed from the client to the server.
 * <p>
 * The principal and credentials information will be extracted from the current security
 * context and passed to the server as part of the invocation object.
 * <p>
 * To avoid potential serialization-based attacks, this implementation interprets the
 * values as {@code String}s and creates a {@code UsernamePasswordAuthenticationToken} on
 * the server side to hold them. If a different token type is required you can override
 * the {@code createAuthenticationRequest} method.
 *
 * @author James Monaghan
 * @author Ben Alex
 * @author Luke Taylor
 */
public class ContextPropagatingRemoteInvocation extends RemoteInvocation {

	private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;

	private static final Log logger = LogFactory.getLog(ContextPropagatingRemoteInvocation.class);

	private final String principal;

	private final String credentials;

	/**
	 * Constructs the object, storing the principal and credentials extracted from the
	 * client-side security context.
	 * @param methodInvocation the method to invoke
	 */
	public ContextPropagatingRemoteInvocation(MethodInvocation methodInvocation) {
		super(methodInvocation);
		Authentication currentUser = SecurityContextHolder.getContext().getAuthentication();
		if (currentUser != null) {
			this.principal = currentUser.getName();
			Object userCredentials = currentUser.getCredentials();
			this.credentials = (userCredentials != null) ? userCredentials.toString() : null;
		}
		else {
			this.credentials = null;
			this.principal = null;
		}
		if (logger.isDebugEnabled()) {
			logger.debug("RemoteInvocation now has principal: " + this.principal);
			if (this.credentials == null) {
				logger.debug("RemoteInvocation now has null credentials.");
			}
		}
	}

	/**
	 * Invoked on the server-side.
	 * <p>
	 * The transmitted principal and credentials will be used to create an unauthenticated
	 * {@code Authentication} instance for processing by the
	 * {@code AuthenticationManager}.
	 * @param targetObject the target object to apply the invocation to
	 * @return the invocation result
	 * @throws NoSuchMethodException if the method name could not be resolved
	 * @throws IllegalAccessException if the method could not be accessed
	 * @throws InvocationTargetException if the method invocation resulted in an exception
	 */
	@Override
	public Object invoke(Object targetObject)
			throws NoSuchMethodException, IllegalAccessException, InvocationTargetException {
		if (this.principal != null) {
			Authentication request = createAuthenticationRequest(this.principal, this.credentials);
			request.setAuthenticated(false);
			SecurityContextHolder.getContext().setAuthentication(request);
			logger.debug(LogMessage.format("Set SecurityContextHolder to contain: %s", request));
		}
		try {
			return super.invoke(targetObject);
		}
		finally {
			SecurityContextHolder.clearContext();
			logger.debug("Cleared SecurityContextHolder.");
		}
	}

	/**
	 * Creates the server-side authentication request object.
	 */
	protected Authentication createAuthenticationRequest(String principal, String credentials) {
		return new UsernamePasswordAuthenticationToken(principal, credentials);
	}

}
