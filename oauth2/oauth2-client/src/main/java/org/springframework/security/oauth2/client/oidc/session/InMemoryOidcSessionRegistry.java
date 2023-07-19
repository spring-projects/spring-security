/*
 * Copyright 2002-2023 the original author or authors.
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

package org.springframework.security.oauth2.client.oidc.session;

import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Predicate;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.security.oauth2.client.oidc.authentication.logout.LogoutTokenClaimNames;
import org.springframework.security.oauth2.client.oidc.authentication.logout.OidcLogoutToken;

/**
 * An in-memory implementation of {@link OidcSessionRegistry}
 *
 * @author Josh Cummings
 * @since 6.2
 */
public final class InMemoryOidcSessionRegistry implements OidcSessionRegistry {

	private final Log logger = LogFactory.getLog(InMemoryOidcSessionRegistry.class);

	private final Map<String, OidcSessionInformation> sessions = new ConcurrentHashMap<>();

	@Override
	public void saveSessionInformation(OidcSessionInformation info) {
		this.sessions.put(info.getSessionId(), info);
	}

	@Override
	public OidcSessionInformation removeSessionInformation(String clientSessionId) {
		OidcSessionInformation information = this.sessions.remove(clientSessionId);
		if (information != null) {
			this.logger.trace("Removed client session");
		}
		return information;
	}

	@Override
	public Iterable<OidcSessionInformation> removeSessionInformation(OidcLogoutToken token) {
		List<String> audience = token.getAudience();
		String issuer = token.getIssuer().toString();
		String subject = token.getSubject();
		String providerSessionId = token.getSessionId();
		Predicate<OidcSessionInformation> matcher = (providerSessionId != null)
				? sessionIdMatcher(audience, issuer, providerSessionId) : subjectMatcher(audience, issuer, subject);
		if (this.logger.isTraceEnabled()) {
			String message = "Looking up sessions by issuer [%s] and %s [%s]";
			if (providerSessionId != null) {
				this.logger.trace(String.format(message, issuer, LogoutTokenClaimNames.SID, providerSessionId));
			}
			else {
				this.logger.trace(String.format(message, issuer, LogoutTokenClaimNames.SUB, subject));
			}
		}
		int size = this.sessions.size();
		Set<OidcSessionInformation> infos = new HashSet<>();
		this.sessions.values().removeIf((info) -> {
			boolean result = matcher.test(info);
			if (result) {
				infos.add(info);
			}
			return result;
		});
		if (infos.isEmpty()) {
			this.logger.debug("Failed to remove any sessions since none matched");
		}
		else if (this.logger.isTraceEnabled()) {
			String message = "Found and removed %d session(s) from mapping of %d session(s)";
			this.logger.trace(String.format(message, infos.size(), size));
		}
		return infos;
	}

	private static Predicate<OidcSessionInformation> sessionIdMatcher(List<String> audience, String issuer,
			String sessionId) {
		return (session) -> {
			List<String> thatAudience = session.getPrincipal().getAudience();
			String thatIssuer = session.getPrincipal().getIssuer().toString();
			String thatSessionId = session.getPrincipal().getClaimAsString(LogoutTokenClaimNames.SID);
			if (thatAudience == null) {
				return false;
			}
			return !Collections.disjoint(audience, thatAudience) && issuer.equals(thatIssuer)
					&& sessionId.equals(thatSessionId);
		};
	}

	private static Predicate<OidcSessionInformation> subjectMatcher(List<String> audience, String issuer,
			String subject) {
		return (session) -> {
			List<String> thatAudience = session.getPrincipal().getAudience();
			String thatIssuer = session.getPrincipal().getIssuer().toString();
			String thatSubject = session.getPrincipal().getSubject();
			if (thatAudience == null) {
				return false;
			}
			return !Collections.disjoint(audience, thatAudience) && issuer.equals(thatIssuer)
					&& subject.equals(thatSubject);
		};
	}

}
