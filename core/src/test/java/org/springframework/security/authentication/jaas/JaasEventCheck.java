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

package org.springframework.security.authentication.jaas;

import org.springframework.context.ApplicationListener;
import org.springframework.security.authentication.jaas.event.JaasAuthenticationEvent;
import org.springframework.security.authentication.jaas.event.JaasAuthenticationFailedEvent;
import org.springframework.security.authentication.jaas.event.JaasAuthenticationSuccessEvent;

/**
 * @author Ray Krueger
 */
public class JaasEventCheck implements ApplicationListener<JaasAuthenticationEvent> {

	// ~ Instance fields
	// ================================================================================================

	JaasAuthenticationFailedEvent failedEvent;

	JaasAuthenticationSuccessEvent successEvent;

	// ~ Methods
	// ========================================================================================================

	public void onApplicationEvent(JaasAuthenticationEvent event) {
		if (event instanceof JaasAuthenticationFailedEvent) {
			failedEvent = (JaasAuthenticationFailedEvent) event;
		}

		if (event instanceof JaasAuthenticationSuccessEvent) {
			successEvent = (JaasAuthenticationSuccessEvent) event;
		}
	}

}
