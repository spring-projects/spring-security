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

package org.springframework.security.web.firewall;

import java.io.IOException;
import java.util.StringTokenizer;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

/**
 * Request wrapper which ensures values of {@code servletPath} and {@code pathInfo} are
 * returned which are suitable for pattern matching against. It strips out path parameters
 * and extra consecutive '/' characters.
 *
 * <h3>Path Parameters</h3> Parameters (as defined in
 * <a href="https://www.ietf.org/rfc/rfc2396.txt">RFC 2396</a>) are stripped from the path
 * segments of the {@code servletPath} and {@code pathInfo} values of the request.
 * <p>
 * The parameter sequence is demarcated by a semi-colon, so each segment is checked for
 * the occurrence of a ";" character and truncated at that point if it is present.
 * <p>
 * The behaviour differs between servlet containers in how they interpret the servlet
 * spec, which does not clearly state what the behaviour should be. For consistency, we
 * make sure they are always removed, to avoid the risk of URL matching rules being
 * bypassed by the malicious addition of parameters to the path component.
 *
 * @author Luke Taylor
 */
final class RequestWrapper extends FirewalledRequest {

	private final String strippedServletPath;

	private final String strippedPathInfo;

	private boolean stripPaths = true;

	RequestWrapper(HttpServletRequest request) {
		super(request);
		this.strippedServletPath = strip(request.getServletPath());
		String pathInfo = strip(request.getPathInfo());
		if (pathInfo != null && pathInfo.length() == 0) {
			pathInfo = null;
		}
		this.strippedPathInfo = pathInfo;
	}

	/**
	 * Removes path parameters from each path segment in the supplied path and truncates
	 * sequences of multiple '/' characters to a single '/'.
	 * @param path either the {@code servletPath} and {@code pathInfo} from the original
	 * request
	 * @return the supplied value, with path parameters removed and sequences of multiple
	 * '/' characters truncated, or null if the supplied path was null.
	 */
	private String strip(String path) {
		if (path == null) {
			return null;
		}

		int scIndex = path.indexOf(';');

		if (scIndex < 0) {
			int doubleSlashIndex = path.indexOf("//");
			if (doubleSlashIndex < 0) {
				// Most likely case, no parameters in any segment and no '//', so no
				// stripping required
				return path;
			}
		}

		StringTokenizer st = new StringTokenizer(path, "/");
		StringBuilder stripped = new StringBuilder(path.length());

		if (path.charAt(0) == '/') {
			stripped.append('/');
		}

		while (st.hasMoreTokens()) {
			String segment = st.nextToken();
			scIndex = segment.indexOf(';');

			if (scIndex >= 0) {
				segment = segment.substring(0, scIndex);
			}
			stripped.append(segment).append('/');
		}

		// Remove the trailing slash if the original path didn't have one
		if (path.charAt(path.length() - 1) != '/') {
			stripped.deleteCharAt(stripped.length() - 1);
		}

		return stripped.toString();
	}

	@Override
	public String getPathInfo() {
		return this.stripPaths ? this.strippedPathInfo : super.getPathInfo();
	}

	@Override
	public String getServletPath() {
		return this.stripPaths ? this.strippedServletPath : super.getServletPath();
	}

	@Override
	public RequestDispatcher getRequestDispatcher(String path) {
		return this.stripPaths ? new FirewalledRequestAwareRequestDispatcher(path) : super.getRequestDispatcher(path);
	}

	@Override
	public void reset() {
		this.stripPaths = false;
	}

	/**
	 * Ensures {@link FirewalledRequest#reset()} is called prior to performing a forward.
	 * It then delegates work to the {@link RequestDispatcher} from the original
	 * {@link HttpServletRequest}.
	 *
	 * @author Rob Winch
	 */
	private class FirewalledRequestAwareRequestDispatcher implements RequestDispatcher {

		private final String path;

		/**
		 * @param path the {@code path} that will be used to obtain the delegate
		 * {@link RequestDispatcher} from the original {@link HttpServletRequest}.
		 */
		FirewalledRequestAwareRequestDispatcher(String path) {
			this.path = path;
		}

		@Override
		public void forward(ServletRequest request, ServletResponse response) throws ServletException, IOException {
			reset();
			getDelegateDispatcher().forward(request, response);
		}

		@Override
		public void include(ServletRequest request, ServletResponse response) throws ServletException, IOException {
			getDelegateDispatcher().include(request, response);
		}

		private RequestDispatcher getDelegateDispatcher() {
			return RequestWrapper.super.getRequestDispatcher(this.path);
		}

	}

}
