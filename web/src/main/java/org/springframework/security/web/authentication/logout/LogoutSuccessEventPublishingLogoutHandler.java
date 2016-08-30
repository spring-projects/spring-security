/*
 * Copyright 2002-2016 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.web.authentication.logout;

import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.security.authentication.event.LogoutSuccessEvent;
import org.springframework.security.core.Authentication;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * A logout handler which publish a logout success event.
 *
 * @author Kazuki Shimizu
 * @since 4.2
 */
public final class LogoutSuccessEventPublishingLogoutHandler
		implements LogoutHandler, ApplicationEventPublisherAware {

	private ApplicationEventPublisher applicationEventPublisher;

	/**
	 * {@inheritDoc}
	 */
	public void logout(HttpServletRequest request, HttpServletResponse response,
						Authentication authentication) {
		if (authentication == null) {
			return;
		}
		if (this.applicationEventPublisher == null) {
			return;
		}
		this.applicationEventPublisher.publishEvent(new LogoutSuccessEvent(authentication));
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void setApplicationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
		this.applicationEventPublisher = applicationEventPublisher;
	}

}
