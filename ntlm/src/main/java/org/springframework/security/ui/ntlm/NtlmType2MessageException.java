/* Copyright 2004-2007 Acegi Technology Pty Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.ui.ntlm;

import org.acegisecurity.Authentication;
import org.acegisecurity.context.SecurityContextHolder;

/**
 * Contains the NTLM Type 2 message that is sent back to the client during
 * negotiations.
 *
 * @author Edward Smith
 */
public class NtlmType2MessageException extends NtlmBaseException {

	private static final long serialVersionUID = 1L;

	private final Authentication auth;

	public NtlmType2MessageException(final String type2Msg) {
		super("NTLM " + type2Msg);
		auth = SecurityContextHolder.getContext().getAuthentication();
	}

	/**
	 * Preserve the existing <code>Authentication</code> object each time
	 * Internet Explorer does a POST.
	 */
	public void preserveAuthentication() {
		if (auth != null) {
			SecurityContextHolder.getContext().setAuthentication(auth);
        }
    }

}
