/*
 * Copyright 2002-2021 the original author or authors.
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

package org.springframework.security.authorization;

import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.security.authorization.event.AuthorizationFailureEvent;
import org.springframework.security.authorization.event.AuthorizationSuccessEvent;

/**
 * Default implementation of {@link AuthorizationEventPublisher}
 *
 * @author Parikshit Dutta
 * @since 5.5
 */
public class DefaultAuthorizationEventPublisher implements AuthorizationEventPublisher, ApplicationEventPublisherAware {

	private ApplicationEventPublisher applicationEventPublisher;

	public DefaultAuthorizationEventPublisher() {
		this(null);
	}

	public DefaultAuthorizationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
		this.applicationEventPublisher = applicationEventPublisher;
	}

	@Override
	public void setApplicationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
		this.applicationEventPublisher = applicationEventPublisher;
	}

	@Override
	public void publishAuthorizationSuccess(AuthorizationDecision authorizationDecision) {
		if (this.applicationEventPublisher != null) {
			this.applicationEventPublisher.publishEvent(new AuthorizationSuccessEvent(authorizationDecision));
		}
	}

	@Override
	public void publishAuthorizationFailure(AuthorizationDecision authorizationDecision) {
		if (this.applicationEventPublisher != null) {
			this.applicationEventPublisher.publishEvent(new AuthorizationFailureEvent(authorizationDecision));
		}
	}

}
