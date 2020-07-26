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

package org.springframework.security.authentication.event;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.context.ApplicationListener;
import org.springframework.util.ClassUtils;

/**
 * Outputs authentication-related application events to Commons Logging.
 * <p>
 * All authentication events are logged at the warning level.
 *
 * @author Ben Alex
 */
public class LoggerListener implements ApplicationListener<AbstractAuthenticationEvent> {

	private static final Log logger = LogFactory.getLog(LoggerListener.class);

	/**
	 * If set to true, {@link InteractiveAuthenticationSuccessEvent} will be logged
	 * (defaults to true)
	 */
	private boolean logInteractiveAuthenticationSuccessEvents = true;

	@Override
	public void onApplicationEvent(AbstractAuthenticationEvent event) {
		if (!this.logInteractiveAuthenticationSuccessEvents && event instanceof InteractiveAuthenticationSuccessEvent) {
			return;
		}

		if (logger.isWarnEnabled()) {
			final StringBuilder builder = new StringBuilder();
			builder.append("Authentication event ");
			builder.append(ClassUtils.getShortName(event.getClass()));
			builder.append(": ");
			builder.append(event.getAuthentication().getName());
			builder.append("; details: ");
			builder.append(event.getAuthentication().getDetails());

			if (event instanceof AbstractAuthenticationFailureEvent) {
				builder.append("; exception: ");
				builder.append(((AbstractAuthenticationFailureEvent) event).getException().getMessage());
			}

			logger.warn(builder.toString());
		}
	}

	public boolean isLogInteractiveAuthenticationSuccessEvents() {
		return this.logInteractiveAuthenticationSuccessEvents;
	}

	public void setLogInteractiveAuthenticationSuccessEvents(boolean logInteractiveAuthenticationSuccessEvents) {
		this.logInteractiveAuthenticationSuccessEvents = logInteractiveAuthenticationSuccessEvents;
	}

}
