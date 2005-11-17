/* Copyright 2004, 2005 Acegi Technology Pty Limited
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

package org.acegisecurity.wrapper;

import java.security.Principal;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TimeZone;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpSession;

import org.acegisecurity.Authentication;
import org.acegisecurity.AuthenticationTrustResolver;
import org.acegisecurity.AuthenticationTrustResolverImpl;
import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.UserDetails;
import org.acegisecurity.context.SecurityContextHolder;
import org.acegisecurity.intercept.web.SandboxSecurityEnforcementFilter;
import org.acegisecurity.wrapper.redirect.Enumerator;
import org.acegisecurity.wrapper.redirect.FastHttpDateFormat;
import org.acegisecurity.wrapper.redirect.SavedHttpServletRequest;

/**
 * An Acegi Security-aware <code>HttpServletRequestWrapper</code>, which uses
 * the <code>SecurityContext</code>-defined <code>Authentication</code>
 * object for
 * {@link SecurityContextHolderAwareRequestWrapper#isUserInRole(java.lang.String)}
 * and {@link javax.servlet.http.HttpServletRequestWrapper#getRemoteUser()}
 * responses.
 * <p>
 * Provides request parameters, headers, cookies from original requrest or saved request.
 * </p>
 * 
 * @author Orlando Garcia Carmona
 * @author Ben Alex
 * @author Andrey Grebnev <a href="mailto:andrey.grebnev@blandware.com">&lt;andrey.grebnev@blandware.com&gt;</a>
 * @version $Id$
 */
public class SandboxSecurityContextHolderAwareRequestWrapper extends
		HttpServletRequestWrapper {

	// ~ Static fields ========================================================

	protected static final TimeZone GMT_ZONE = TimeZone.getTimeZone("GMT");

	/**
	 * The default Locale if none are specified.
	 */
	protected static Locale defaultLocale = Locale.getDefault();

	// ~ Instance fields
	// ========================================================

	/**
	 * Authentication trust resolver.
	 */
	private AuthenticationTrustResolver authenticationTrustResolver = new AuthenticationTrustResolverImpl();

	/**
	 * The set of SimpleDateFormat formats to use in getDateHeader().
	 * 
	 * Notice that because SimpleDateFormat is not thread-safe, we can't declare
	 * formats[] as a static variable.
	 */
	protected SimpleDateFormat formats[] = new SimpleDateFormat[3];

	/**
	 * Saved request (to be resumed after authentication)
	 */
	protected SavedHttpServletRequest savedRequest = null;

	// ~ Constructors
	// ===========================================================

	/**
	 * The class' primary constructor.
	 * 
	 * @param request HttpServletRequest
	 */
	public SandboxSecurityContextHolderAwareRequestWrapper(HttpServletRequest request) {

		// First do what the parent class needs to.
		super(request);

		// Return if there isn't an existing HttpSession
		HttpSession session = request.getSession(false);
		if (session != null) {

			// We know there's an existing HttpSession, so see if it has a
			// saved request (placed there by SecurityEnforcementFilter).
			SavedHttpServletRequest saved = (SavedHttpServletRequest) session
					.getAttribute(SandboxSecurityEnforcementFilter.SAVED_REQUEST_SESSION_ATTRIBUTE);
			if (saved != null) {

				// We know there's a saved request, so see if it has a
				// saved "root" request URI to forward to.
				String requestURI = saved.getRequestURI();
				if (requestURI != null) {

					// We know there's a saved "root" request URI, so see if
					// it's the
					// same one specified by this request.
					if (requestURI.equals(request.getRequestURI())) {

						// They're the same "root" request URIs, so get the
						// saved request and remove it from the HttpSession
						// since we only want to process it once.
						savedRequest = saved;
						session
								.removeAttribute(SandboxSecurityEnforcementFilter.SAVED_REQUEST_SESSION_ATTRIBUTE);

						formats[0] = new SimpleDateFormat(
								"EEE, dd MMM yyyy HH:mm:ss zzz", Locale.US);
						formats[1] = new SimpleDateFormat(
								"EEEEEE, dd-MMM-yy HH:mm:ss zzz", Locale.US);
						formats[2] = new SimpleDateFormat(
								"EEE MMMM d HH:mm:ss yyyy", Locale.US);

						formats[0].setTimeZone(GMT_ZONE);
						formats[1].setTimeZone(GMT_ZONE);
						formats[2].setTimeZone(GMT_ZONE);
					}

				}

			}

		}

		return;

	}

	// ~ Methods
	// ================================================================

	/**
	 * Returns the principal's name, as obtained from the
	 * <code>SecurityContextHolder</code>. Properly handles both
	 * <code>String</code>-based and <code>UserDetails</code>-based
	 * principals.
	 * 
	 * @return the username or <code>null</code> if unavailable
	 */
	public String getRemoteUser() {
		Authentication auth = getAuthentication();

		if ((auth == null) || (auth.getPrincipal() == null)) {
			return null;
		}

		if (auth.getPrincipal() instanceof UserDetails) {
			return ((UserDetails) auth.getPrincipal()).getUsername();
		}

		return auth.getPrincipal().toString();
	}

	/**
	 * Simple searches for an exactly matching {@link
	 * GrantedAuthority#getAuthority()}.
	 * 
	 * <p>
	 * Will always return <code>false</code> if the
	 * <code>SecurityContextHolder</code> contains an
	 * <code>Authentication</code> with
	 * <code>null</code><code>principal</code> and/or
	 * <code>GrantedAuthority[]</code> objects.
	 * </p>
	 * 
	 * @param role the <code>GrantedAuthority</code><code>String</code> representation to check for.
	 * @return <code>true</code> if an <b>exact</b> (case sensitive) matching granted authority is located, <code>false</code> otherwise.
	 */
	public boolean isUserInRole(String role) {
		return isGranted(role);
	}

	/**
	 * Returns the <code>Authentication</code> (which is a subclass of
	 * <code>Principal</code>), or <code>null</code> if unavailable.
	 * 
	 * <p>
	 * Note: Override this method in order to workaround the problem in Sun Java
	 * System Application Server 8.1 PE
	 * </p>
	 * 
	 * @return the <code>Authentication</code>, or <code>null</code>
	 */
	public Principal getUserPrincipal() {
		Authentication auth = getAuthentication();

		if ((auth == null) || (auth.getPrincipal() == null)) {
			return null;
		}

		return auth;
	}

	/**
	 * Obtain the current active <code>Authentication</code>
	 * 
	 * @return the authentication object or <code>null</code>
	 */
	private Authentication getAuthentication() {
		Authentication auth = SecurityContextHolder.getContext()
				.getAuthentication();

		if (!authenticationTrustResolver.isAnonymous(auth)) {
			return auth;
		}

		return null;
	}

	/**
	 * Determines if principal has been granted a given role.
	 * 
	 * @param role The role being tested.
	 * @return True if principal has been granted the given role.
	 */
	private boolean isGranted(String role) {
		Authentication auth = getAuthentication();

		if ((auth == null) || (auth.getPrincipal() == null)
				|| (auth.getAuthorities() == null)) {
			return false;
		}

		for (int i = 0; i < auth.getAuthorities().length; i++) {
			if (role.equals(auth.getAuthorities()[i].getAuthority())) {
				return true;
			}
		}

		return false;
	}

	/**
	 * The default behavior of this method is to return getMethod() on the
	 * wrapped request object.
	 */
	public String getMethod() {
		if (savedRequest == null) {
			return super.getMethod();
		} else {
			return savedRequest.getMethod();
		}
	}

	/**
	 * The default behavior of this method is to return getHeader(String name)
	 * on the wrapped request object.
	 */
	public String getHeader(String name) {
		if (savedRequest == null) {
			return super.getHeader(name);
		} else {
			String header = null;
			Iterator iterator = savedRequest.getHeaderValues(name);
			while (iterator.hasNext()) {
				header = (String) iterator.next();
				break;
			}
			return header;
		}
	}

	/**
	 * The default behavior of this method is to return getIntHeader(String
	 * name) on the wrapped request object.
	 */
	public int getIntHeader(String name) {
		if (savedRequest == null) {
			return super.getIntHeader(name);
		} else {
			String value = getHeader(name);
			if (value == null) {
				return (-1);
			} else {
				return (Integer.parseInt(value));
			}
		}
	}

	/**
	 * The default behavior of this method is to return getDateHeader(String
	 * name) on the wrapped request object.
	 */
	public long getDateHeader(String name) {
		if (savedRequest == null) {
			return super.getDateHeader(name);
		} else {
			String value = getHeader(name);
			if (value == null)
				return (-1L);

			// Attempt to convert the date header in a variety of formats
			long result = FastHttpDateFormat.parseDate(value, formats);
			if (result != (-1L)) {
				return result;
			}
			throw new IllegalArgumentException(value);
		}
	}

	/**
	 * The default behavior of this method is to return getHeaderNames() on the
	 * wrapped request object.
	 */
	public Enumeration getHeaderNames() {
		if (savedRequest == null) {
			return super.getHeaderNames();
		} else {
			return new Enumerator(savedRequest.getHeaderNames());
		}
	}

	/**
	 * The default behavior of this method is to return getHeaders(String name)
	 * on the wrapped request object.
	 */
	public Enumeration getHeaders(String name) {
		if (savedRequest == null) {
			return super.getHeaders(name);
		} else {
			return new Enumerator(savedRequest.getHeaderValues(name));
		}
	}

	/**
	 * The default behavior of this method is to return getCookies() on the
	 * wrapped request object.
	 */
	public Cookie[] getCookies() {
		if (savedRequest == null) {
			return super.getCookies();
		} else {
			List cookies = savedRequest.getCookies();
			return (Cookie[]) cookies.toArray(new Cookie[cookies.size()]);
		}
	}

	/**
	 * The default behavior of this method is to return
	 * getParameterValues(String name) on the wrapped request object.
	 */
	public String[] getParameterValues(String name) {
		if (savedRequest == null) {
			return super.getParameterValues(name);
		} else {
			return savedRequest.getParameterValues(name);
		}
	}

	/**
	 * The default behavior of this method is to return getParameterNames() on
	 * the wrapped request object.
	 */
	public Enumeration getParameterNames() {
		if (savedRequest == null) {
			return super.getParameterNames();
		} else {
			return new Enumerator(savedRequest.getParameterNames());
		}
	}

	/**
	 * The default behavior of this method is to return getParameterMap() on the
	 * wrapped request object.
	 */
	public Map getParameterMap() {
		if (savedRequest == null) {
			return super.getParameterMap();
		} else {
			return savedRequest.getParameterMap();
		}
	}

	/**
	 * The default behavior of this method is to return getParameter(String
	 * name) on the wrapped request object.
	 */
	public String getParameter(String name) {

		/*
		 * if (savedRequest == null) { return super.getParameter(name); } else {
		 * String value = null; String[] values =
		 * savedRequest.getParameterValues(name); if (values == null) return
		 * null; for (int i = 0; i < values.length; i++) { value = values[i];
		 * break; } return value; }
		 */

		// We do not get value from super.getParameter because
		// of a bug in Jetty servlet-container.
		String value = null;
		String[] values = null;
		if (savedRequest == null) {
			values = super.getParameterValues(name);
		} else {
			values = savedRequest.getParameterValues(name);
		}

		if (values == null)
			return null;
		for (int i = 0; i < values.length; i++) {
			value = values[i];
			break;
		}
		return value;

	}

	/**
	 * The default behavior of this method is to return getLocales() on the
	 * wrapped request object.
	 */
	public Enumeration getLocales() {
		if (savedRequest == null) {
			return super.getLocales();
		} else {
			Iterator iterator = savedRequest.getLocales();
			if (iterator.hasNext()) {
				return new Enumerator(iterator);
			} else {
				ArrayList results = new ArrayList();
				results.add(defaultLocale);
				return new Enumerator(results.iterator());
			}
		}
	}

	/**
	 * The default behavior of this method is to return getLocale() on the
	 * wrapped request object.
	 */
	public Locale getLocale() {
		if (savedRequest == null) {
			return super.getLocale();
		} else {
			Locale locale = null;
			Iterator iterator = savedRequest.getLocales();
			while (iterator.hasNext()) {
				locale = (Locale) iterator.next();
				break;
			}
			if (locale == null) {
				return defaultLocale;
			} else {
				return locale;
			}
		}
	}

}
