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

package org.acegisecurity.ui.ntlm;

import org.acegisecurity.AuthenticationException;

/**
 * Base class for NTLM exceptions so that it is easier to distinguish them
 * from other <code>AuthenticationException</code>s in the
 * {@link NtlmProcessingFilterEntryPoint}.  Marked as <code>abstract</code>
 * since this exception is never supposed to be instantiated.
 *
 * @author Edward Smith
 */
public abstract class NtlmBaseException extends AuthenticationException {

	public NtlmBaseException(final String msg) {
		super(msg);
	}

}
