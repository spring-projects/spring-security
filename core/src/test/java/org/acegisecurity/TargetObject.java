/* Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
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

package org.acegisecurity;

import org.acegisecurity.context.SecurityContextHolder;


/**
 * Represents a secured object.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class TargetObject implements ITargetObject {
    //~ Methods ========================================================================================================

    public Integer computeHashCode(String input) {
        return new Integer(input.hashCode());
    }

    public int countLength(String input) {
        return input.length();
    }

    /**
     * Returns the lowercase string, followed by security environment information.
     *
     * @param input the message to make lowercase
     *
     * @return the lowercase message, a space, the <code>Authentication</code> class that was on the
     *         <code>SecurityContext</code> at the time of method invocation, and a boolean indicating if the
     *         <code>Authentication</code> object is authenticated or not
     */
    public String makeLowerCase(String input) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        if (auth == null) {
            return input.toLowerCase() + " Authentication empty";
        } else {
            return input.toLowerCase() + " " + auth.getClass().getName() + " " + auth.isAuthenticated();
        }
    }

    /**
     * Returns the uppercase string, followed by security environment information.
     *
     * @param input the message to make uppercase
     *
     * @return the uppercase message, a space, the <code>Authentication</code> class that was on the
     *         <code>SecurityContext</code> at the time of method invocation, and a boolean indicating if the
     *         <code>Authentication</code> object is authenticated or not
     */
    public String makeUpperCase(String input) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        return input.toUpperCase() + " " + auth.getClass().getName() + " " + auth.isAuthenticated();
    }

    /**
     * Delegates through to the {@link #makeLowerCase(String)} method.
     *
     * @param input the message to be made lower-case
     *
     * @return DOCUMENT ME!
     */
    public String publicMakeLowerCase(String input) {
        return this.makeLowerCase(input);
    }
}
