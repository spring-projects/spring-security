/*
 * Copyright 2010-2016 the original author or authors.
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
package org.springframework.security.web.jaasapi;

import java.io.IOException;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;

import javax.security.auth.Subject;
import javax.security.auth.login.LoginContext;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.springframework.security.authentication.jaas.JaasAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.GenericFilterBean;

/**
 * <p>
 * A <code>Filter</code> which attempts to obtain a JAAS <code>Subject</code> and continue
 * the <code>FilterChain</code> running as that <code>Subject</code>.
 * </p>
 * <p>
 * By using this <code>Filter</code> in conjunction with Spring's
 * <code>JaasAuthenticationProvider</code> both Spring's <code>SecurityContext</code> and
 * a JAAS <code>Subject</code> can be populated simultaneously. This is useful when
 * integrating with code that requires a JAAS <code>Subject</code> to be populated.
 * </p>
 *
 * @author Rob Winch
 * @see #doFilter(ServletRequest, ServletResponse, FilterChain)
 * @see #obtainSubject(ServletRequest)
 */
public class JaasApiIntegrationFilter extends GenericFilterBean {
	// ~ Instance fields
	// ================================================================================================

	private boolean createEmptySubject;

	// ~ Methods
	// ========================================================================================================

	/**
	 * <p>
	 * Attempts to obtain and run as a JAAS <code>Subject</code> using
	 * {@link #obtainSubject(ServletRequest)}.
	 * </p>
	 *
	 * <p>
	 * If the <code>Subject</code> is <code>null</code> and <tt>createEmptySubject</tt> is
	 * <code>true</code>, an empty, writeable <code>Subject</code> is used. This allows
	 * for the <code>Subject</code> to be populated at the time of login. If the
	 * <code>Subject</code> is <code>null</code>, the <code>FilterChain</code> continues
	 * with no additional processing. If the <code>Subject</code> is not <code>null</code>
	 * , the <code>FilterChain</code> is ran with
	 * {@link Subject#doAs(Subject, PrivilegedExceptionAction)} in conjunction with the
	 * <code>Subject</code> obtained.
	 * </p>
	 */
	public final void doFilter(final ServletRequest request,
			final ServletResponse response, final FilterChain chain)
			throws ServletException, IOException {

		Subject subject = obtainSubject(request);
		if (subject == null && createEmptySubject) {
			if (logger.isDebugEnabled()) {
				logger.debug("Subject returned was null and createEmtpySubject is true; creating new empty subject to run as.");
			}
			subject = new Subject();
		}
		if (subject == null) {
			if (logger.isDebugEnabled()) {
				logger.debug("Subject is null continue running with no Subject.");
			}
			chain.doFilter(request, response);
			return;
		}
		final PrivilegedExceptionAction<Object> continueChain = () -> {
			chain.doFilter(request, response);
			return null;
		};

		if (logger.isDebugEnabled()) {
			logger.debug("Running as Subject " + subject);
		}
		try {
			Subject.doAs(subject, continueChain);
		}
		catch (PrivilegedActionException e) {
			throw new ServletException(e.getMessage(), e);
		}
	}

	/**
	 * <p>
	 * Obtains the <code>Subject</code> to run as or <code>null</code> if no
	 * <code>Subject</code> is available.
	 * </p>
	 * <p>
	 * The default implementation attempts to obtain the <code>Subject</code> from the
	 * <code>SecurityContext</code>'s <code>Authentication</code>. If it is of type
	 * <code>JaasAuthenticationToken</code> and is authenticated, the <code>Subject</code>
	 * is returned from it. Otherwise, <code>null</code> is returned.
	 * </p>
	 *
	 * @param request the current <code>ServletRequest</code>
	 * @return the Subject to run as or <code>null</code> if no <code>Subject</code> is
	 * available.
	 */
	protected Subject obtainSubject(ServletRequest request) {
		Authentication authentication = SecurityContextHolder.getContext()
				.getAuthentication();
		if (logger.isDebugEnabled()) {
			logger.debug("Attempting to obtainSubject using authentication : "
					+ authentication);
		}
		if (authentication == null) {
			return null;
		}
		if (!authentication.isAuthenticated()) {
			return null;
		}
		if (!(authentication instanceof JaasAuthenticationToken)) {
			return null;
		}
		JaasAuthenticationToken token = (JaasAuthenticationToken) authentication;
		LoginContext loginContext = token.getLoginContext();
		if (loginContext == null) {
			return null;
		}
		return loginContext.getSubject();
	}

	/**
	 * Sets <code>createEmptySubject</code>. If the value is <code>true</code>, and
	 * {@link #obtainSubject(ServletRequest)} returns <code>null</code>, an empty,
	 * writeable <code>Subject</code> is created instead. Otherwise no
	 * <code>Subject</code> is used. The default is <code>false</code>.
	 *
	 * @param createEmptySubject the new value
	 */
	public final void setCreateEmptySubject(boolean createEmptySubject) {
		this.createEmptySubject = createEmptySubject;
	}
}
