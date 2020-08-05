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

package org.springframework.security.web.access.channel;

/**
 * Commences a secure channel by retrying the original request using HTTPS.
 * <p>
 * This entry point should suffice in most circumstances. However, it is not intended to
 * properly handle HTTP POSTs or other usage where a standard redirect would cause an
 * issue.
 * </p>
 *
 * @author Ben Alex
 */
public class RetryWithHttpsEntryPoint extends AbstractRetryEntryPoint {

	public RetryWithHttpsEntryPoint() {
		super("https://", 443);
	}

	protected Integer getMappedPort(Integer mapFromPort) {
		return getPortMapper().lookupHttpsPort(mapFromPort);
	}

}
