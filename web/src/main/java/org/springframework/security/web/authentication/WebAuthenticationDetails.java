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

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

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
		this.remoteAddress = request.getRemoteAddr();
		HttpSession session = request.getSession(false);
		this.sessionId = (session != null) ? session.getId() : null;
	}

	/**
	 * Constructor to add Jackson2 serialize/deserialize support
	 * @param remoteAddress remote address of current request
	 * @param sessionId session id
	 */
	private WebAuthenticationDetails(final String remoteAddress, final String sessionId) {
		this.remoteAddress = remoteAddress;
		this.sessionId = sessionId;
	}

	@Override
	public boolean equals(Object obj) {
		if (obj instanceof WebAuthenticationDetails) {
			WebAuthenticationDetails other = (WebAuthenticationDetails) obj;
			if ((this.remoteAddress == null) && (other.getRemoteAddress() != null)) {
				return false;
			}
			if ((this.remoteAddress != null) && (other.getRemoteAddress() == null)) {
				return false;
			}
			if (this.remoteAddress != null) {
				if (!this.remoteAddress.equals(other.getRemoteAddress())) {
					return false;
				}
			}
			if ((this.sessionId == null) && (other.getSessionId() != null)) {
				return false;
			}
			if ((this.sessionId != null) && (other.getSessionId() == null)) {
				return false;
			}
			if (this.sessionId != null) {
				if (!this.sessionId.equals(other.getSessionId())) {
					return false;
				}
			}
			return true;
		}
		return false;
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
	public int hashCode() {
		int code = 7654;
		if (this.remoteAddress != null) {
			code = code * (this.remoteAddress.hashCode() % 7);
		}
		if (this.sessionId != null) {
			code = code * (this.sessionId.hashCode() % 7);
		}
		return code;
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append(super.toString()).append(": ");
		sb.append("RemoteIpAddress: ").append(this.getRemoteAddress()).append("; ");
		sb.append("SessionId: ").append(this.getSessionId());
		return sb.toString();
	}

}
