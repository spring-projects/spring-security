/* Copyright 2004 Acegi Technology Pty Limited
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

package net.sf.acegisecurity.intercept;

import net.sf.acegisecurity.Authentication;


/**
 * A return object received by {@link AbstractSecurityInterceptor} subclasses.
 * 
 * <P>
 * This class reflects the status of the security interception, so that the
 * final call to <code>AbstractSecurityInterceptor</code> can tidy up
 * correctly.
 * </p>
 * 
 * <P>
 * Whilst this class currently only wraps a single object, it has been modelled
 * as a class so that future changes to the operation of
 * <code>AbstractSecurityInterceptor</code> are abstracted from subclasses.
 * </p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public class InterceptorStatusToken {
    //~ Instance fields ========================================================

    private Authentication authenticated;

    //~ Methods ================================================================

    public void setAuthenticated(Authentication authenticated) {
        this.authenticated = authenticated;
    }

    public Authentication getAuthenticated() {
        return authenticated;
    }
}
