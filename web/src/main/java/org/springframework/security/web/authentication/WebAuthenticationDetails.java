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

package org.springframework.security.web.authentication;

import java.io.Serializable;
import java.util.Objects;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;

import org.springframework.security.core.SpringSecurityCoreVersion;

/**
 * A holder of selected HTTP details related to a web authentication request.
 *
 * @author Ben Alex
 * @author Luke Taylor
 */
public class WebAuthenticationDetails implements Serializable {

	private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;

	private final String remoteAddress;

	private final String sessionId;

	/**
	 * Records the remote address and will also set the session Id if a session already
	 * exists (it won't create one).
	 * @param request that the authentication request was received from
	 */
	public WebAuthenticationDetails(HttpServletRequest request) {
		this(request.getRemoteAddr(), extractSessionId(request));
	}

	/**
	 * Constructor to add Jackson2 serialize/deserialize support
	 * @param remoteAddress remote address of current request
	 * @param sessionId session id
	 * @since 5.7
	 */
	public WebAuthenticationDetails(String remoteAddress, String sessionId) {
		this.remoteAddress = remoteAddress;
		this.sessionId = sessionId;
	}

	private static String extractSessionId(HttpServletRequest request) {
		HttpSession session = request.getSession(false);
		return (session != null) ? session.getId() : null;
	}

	/**
	 * Indicates the TCP/IP address the authentication request was received from.
	 * @return the address
	 */
	public String getRemoteAddress() {
		return this.remoteAddress;
	}

	/**
	 * Indicates the <code>HttpSession</code> id the authentication request was received
	 * from.
	 * @return the session ID
	 */
	public String getSessionId() {
		return this.sessionId;
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) {
			return true;
		}
		if (o == null || getClass() != o.getClass()) {
			return false;
		}
		WebAuthenticationDetails that = (WebAuthenticationDetails) o;
		return Objects.equals(this.remoteAddress, that.remoteAddress) && Objects.equals(this.sessionId, that.sessionId);
	}

	@Override
	public int hashCode() {
		return Objects.hash(this.remoteAddress, this.sessionId);
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append(getClass().getSimpleName()).append(" [");
		sb.append("RemoteIpAddress=").append(this.getRemoteAddress()).append(", ");
		sb.append("SessionId=").append(this.getSessionId()).append("]");
		return sb.toString();
	}

}
