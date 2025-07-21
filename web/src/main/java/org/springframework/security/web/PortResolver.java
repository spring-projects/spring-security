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

package org.springframework.security.web;

import jakarta.servlet.ServletRequest;

/**
 * A <code>PortResolver</code> determines the port a web request was received on.
 *
 * <P>
 * This interface is necessary because <code>ServletRequest.getServerPort()</code> may not
 * return the correct port in certain circumstances. For example, if the browser does not
 * construct the URL correctly after a redirect.
 * </p>
 *
 * @author Ben Alex
 * @deprecated This existed for an old IE bug and is no longer need.
 */
@Deprecated(forRemoval = true, since = "6.5")
public interface PortResolver {

	PortResolver NO_OP = new PortResolver() {

		@Override
		public int getServerPort(ServletRequest request) {
			return request.getServerPort();
		}
	};

	/**
	 * Indicates the port the <code>ServletRequest</code> was received on.
	 * @param request that the method should lookup the port for
	 * @return the port the request was received on
	 */
	int getServerPort(ServletRequest request);

}
