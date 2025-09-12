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

package org.springframework.security.access.event;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.context.ApplicationListener;
import org.springframework.core.log.LogMessage;

/**
 * Outputs interceptor-related application events to Commons Logging.
 * <p>
 * All failures are logged at the warning level, with success events logged at the
 * information level, and public invocation events logged at the debug level.
 * </p>
 *
 * @author Ben Alex
 * @deprecated Logging is now embedded in Spring Security components. If you need further
 * logging, please consider using your own {@link ApplicationListener}
 */
@Deprecated
public class LoggerListener implements ApplicationListener<AbstractAuthorizationEvent> {

	private static final Log logger = LogFactory.getLog(LoggerListener.class);

	@Override
	public void onApplicationEvent(AbstractAuthorizationEvent event) {
		if (event instanceof AuthenticationCredentialsNotFoundEvent) {
			onAuthenticationCredentialsNotFoundEvent((AuthenticationCredentialsNotFoundEvent) event);
		}
		if (event instanceof AuthorizationFailureEvent) {
			onAuthorizationFailureEvent((AuthorizationFailureEvent) event);
		}
		if (event instanceof AuthorizedEvent) {
			onAuthorizedEvent((AuthorizedEvent) event);
		}
		if (event instanceof PublicInvocationEvent) {
			onPublicInvocationEvent((PublicInvocationEvent) event);
		}
	}

	private void onAuthenticationCredentialsNotFoundEvent(AuthenticationCredentialsNotFoundEvent authEvent) {
		logger.warn(LogMessage.format(
				"Security interception failed due to: %s; secure object: %s; configuration attributes: %s",
				authEvent.getCredentialsNotFoundException(), authEvent.getSource(), authEvent.getConfigAttributes()));
	}

	private void onPublicInvocationEvent(PublicInvocationEvent event) {
		logger.info(LogMessage.format("Security interception not required for public secure object: %s",
				event.getSource()));
	}

	private void onAuthorizedEvent(AuthorizedEvent authEvent) {
		logger.info(LogMessage.format(
				"Security authorized for authenticated principal: %s; secure object: %s; configuration attributes: %s",
				authEvent.getAuthentication(), authEvent.getSource(), authEvent.getConfigAttributes()));
	}

	private void onAuthorizationFailureEvent(AuthorizationFailureEvent authEvent) {
		logger.warn(LogMessage.format(
				"Security authorization failed due to: %s; authenticated principal: %s; secure object: %s; configuration attributes: %s",
				authEvent.getAccessDeniedException(), authEvent.getAuthentication(), authEvent.getSource(),
				authEvent.getConfigAttributes()));
	}

}
