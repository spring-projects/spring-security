/* Copyright 2004, 2005 Acegi Technology Pty Limited
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

package net.sf.acegisecurity.context.security;

import net.sf.acegisecurity.context.ContextHolder;


/**
 * A simple static method for quickly accessing the <code>SecureContext</code>.
 * 
 * <p>
 * Expects the <code>ContextHolder</code> to be populated and contain a valid
 * <code>SecureContext</code>.
 * </p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public class SecureContextUtils {
    //~ Methods ================================================================

    public static SecureContext getSecureContext() {
        if ((ContextHolder.getContext() == null)
            || !(ContextHolder.getContext() instanceof SecureContext)) {
            throw new IllegalStateException("ContextHolder invalid: '"
                + ContextHolder.getContext()
                + "': are your filters ordered correctly? HttpSessionContextIntegrationFilter should have already executed by this time (look for it in the stack dump below)");
        }

        return (SecureContext) ContextHolder.getContext();
    }
}
