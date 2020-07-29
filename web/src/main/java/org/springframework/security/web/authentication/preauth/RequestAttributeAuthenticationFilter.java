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

package org.springframework.security.web.authentication.preauth;

import javax.servlet.http.HttpServletRequest;

import org.springframework.util.Assert;

/**
 * A simple pre-authenticated filter which obtains the username from request attributes,
 * for use with SSO systems such as
 * <a href="https://webauth.stanford.edu/manual/mod/mod_webauth.html#java">Stanford
 * WebAuth</a> or <a href=
 * "https://wiki.shibboleth.net/confluence/display/SHIB2/NativeSPJavaInstall">Shibboleth</a>.
 * <p>
 * As with most pre-authenticated scenarios, it is essential that the external
 * authentication system is set up correctly as this filter does no authentication
 * whatsoever.
 * <p>
 * The property {@code principalEnvironmentVariable} is the name of the request attribute
 * that contains the username. It defaults to "REMOTE_USER" for compatibility with WebAuth
 * and Shibboleth.
 * <p>
 * If the environment variable is missing from the request,
 * {@code getPreAuthenticatedPrincipal} will throw an exception. You can override this
 * behaviour by setting the {@code exceptionIfVariableMissing} property.
 *
 * @author Milan Sevcik
 * @since 4.2
 */
public class RequestAttributeAuthenticationFilter extends AbstractPreAuthenticatedProcessingFilter {

	private String principalEnvironmentVariable = "REMOTE_USER";

	private String credentialsEnvironmentVariable;

	private boolean exceptionIfVariableMissing = true;

	/**
	 * Read and returns the variable named by {@code principalEnvironmentVariable} from
	 * the request.
	 * @throws PreAuthenticatedCredentialsNotFoundException if the environment variable is
	 * missing and {@code exceptionIfVariableMissing} is set to {@code true}.
	 */
	@Override
	protected Object getPreAuthenticatedPrincipal(HttpServletRequest request) {
		String principal = (String) request.getAttribute(this.principalEnvironmentVariable);

		if (principal == null && this.exceptionIfVariableMissing) {
			throw new PreAuthenticatedCredentialsNotFoundException(
					this.principalEnvironmentVariable + " variable not found in request.");
		}

		return principal;
	}

	/**
	 * Credentials aren't usually applicable, but if a
	 * {@code credentialsEnvironmentVariable} is set, this will be read and used as the
	 * credentials value. Otherwise a dummy value will be used.
	 */
	@Override
	protected Object getPreAuthenticatedCredentials(HttpServletRequest request) {
		if (this.credentialsEnvironmentVariable != null) {
			return request.getAttribute(this.credentialsEnvironmentVariable);
		}

		return "N/A";
	}

	public void setPrincipalEnvironmentVariable(String principalEnvironmentVariable) {
		Assert.hasText(principalEnvironmentVariable, "principalEnvironmentVariable must not be empty or null");
		this.principalEnvironmentVariable = principalEnvironmentVariable;
	}

	public void setCredentialsEnvironmentVariable(String credentialsEnvironmentVariable) {
		Assert.hasText(credentialsEnvironmentVariable, "credentialsEnvironmentVariable must not be empty or null");
		this.credentialsEnvironmentVariable = credentialsEnvironmentVariable;
	}

	/**
	 * Defines whether an exception should be raised if the principal variable is missing.
	 * Defaults to {@code true}.
	 * @param exceptionIfVariableMissing set to {@code false} to override the default
	 * behaviour and allow the request to proceed if no variable is found.
	 */
	public void setExceptionIfVariableMissing(boolean exceptionIfVariableMissing) {
		this.exceptionIfVariableMissing = exceptionIfVariableMissing;
	}

}
