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

import org.springframework.context.ApplicationEvent;

/**
 * Abstract superclass for all security interception related events.
 *
 * @author Ben Alex
 */
public abstract class AbstractAuthorizationEvent extends ApplicationEvent {

	/**
	 * Construct the event, passing in the secure object being intercepted.
	 * @param secureObject the secure object
	 */
	public AbstractAuthorizationEvent(Object secureObject) {
		super(secureObject);
	}

}
