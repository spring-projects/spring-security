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

package net.sf.acegisecurity;

import net.sf.acegisecurity.context.Context;
import net.sf.acegisecurity.context.ContextHolder;
import net.sf.acegisecurity.context.security.SecureContext;


/**
 * Represents a secured object.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class TargetObject implements ITargetObject {
    //~ Methods ================================================================

    public Integer computeHashCode(String input) {
        return new Integer(input.hashCode());
    }

    public int countLength(String input) {
        return input.length();
    }

    /**
     * Returns the lowercase string, followed by security environment
     * information.
     *
     * @param input the message to make lowercase
     *
     * @return the lowercase message, a space, the <code>Authentication</code>
     *         class that was on the <code>ContextHolder</code> at the time of
     *         method invocation, and a boolean indicating if the
     *         <code>Authentication</code> object is authenticated or not
     */
    public String makeLowerCase(String input) {
        Context context = ContextHolder.getContext();

        if ((context != null) && (context instanceof SecureContext)) {
            Authentication auth = ((SecureContext) context).getAuthentication();

            if (auth == null) {
                return input.toLowerCase() + " Authentication empty";
            } else {
                return input.toLowerCase() + " " + auth.getClass().getName()
                + " " + auth.isAuthenticated();
            }
        } else {
            return input.toLowerCase() + " ContextHolder Not Security Aware";
        }
    }

    /**
     * Returns the uppercase string, followed by security environment
     * information.
     *
     * @param input the message to make uppercase
     *
     * @return the uppercase message, a space, the <code>Authentication</code>
     *         class that was on the <code>ContextHolder</code> at the time of
     *         method invocation, and a boolean indicating if the
     *         <code>Authentication</code> object is authenticated or not
     *
     * @throws AccessDeniedException if for some reason this method was being
     *         called and the <code>ContextHolder</code> was <code>null</code>
     *         or did not hold a <code>SecureContext</code>
     */
    public String makeUpperCase(String input) {
        Context context = ContextHolder.getContext();

        if ((context == null) || !(context instanceof SecureContext)) {
            throw new AccessDeniedException(
                "For some reason the SecurityInterceptor allowed this call, meaning the ContextHolder should have been populated, but it was not.");
        }

        Authentication auth = ((SecureContext) context).getAuthentication();

        return input.toUpperCase() + " " + auth.getClass().getName() + " "
        + auth.isAuthenticated();
    }

    /**
     * Delegates through to the {@link #toLowerCase(String)} method.
     *
     * @param input the method to be made uppercase
     *
     * @return
     */
    public String publicMakeLowerCase(String input) {
        return this.makeLowerCase(input);
    }
}
