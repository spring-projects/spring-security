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

package net.sf.acegisecurity.context;

import net.sf.acegisecurity.Authentication;


/**
 * Associates a given {@link Authentication} with the current execution thread,
 * along with new threads the current execution thread may spawn.
 *
 * @author Ben Alex
 * @version $Id$
 *
 * @see java.lang.InheritableThreadLocal
 */
public class SecurityContext {
    //~ Static fields/initializers =============================================

    private static InheritableThreadLocal authenticationHolder = new InheritableThreadLocal();

    //~ Methods ================================================================

    public static void setAuthentication(Authentication authentication) {
        authenticationHolder.set(authentication);
    }

    public static Authentication getAuthentication() {
        return (Authentication) authenticationHolder.get();
    }
}
