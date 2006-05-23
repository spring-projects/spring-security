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

package org.acegisecurity.intercept;

import org.acegisecurity.Authentication;
import org.acegisecurity.ConfigAttributeDefinition;


/**
 * A return object received by {@link AbstractSecurityInterceptor} subclasses.<P>This class reflects the status of
 * the security interception, so that the final call to {@link
 * org.acegisecurity.intercept.AbstractSecurityInterceptor#afterInvocation(InterceptorStatusToken, Object)} can tidy
 * up correctly.</p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public class InterceptorStatusToken {
    //~ Instance fields ================================================================================================

    private Authentication authentication;
    private ConfigAttributeDefinition attr;
    private Object secureObject;
    private boolean contextHolderRefreshRequired;

    //~ Constructors ===================================================================================================

    public InterceptorStatusToken(Authentication authentication, boolean contextHolderRefreshRequired,
        ConfigAttributeDefinition attr, Object secureObject) {
        this.authentication = authentication;
        this.contextHolderRefreshRequired = contextHolderRefreshRequired;
        this.attr = attr;
        this.secureObject = secureObject;
    }

    //~ Methods ========================================================================================================

    public ConfigAttributeDefinition getAttr() {
        return attr;
    }

    public Authentication getAuthentication() {
        return authentication;
    }

    public Object getSecureObject() {
        return secureObject;
    }

    public boolean isContextHolderRefreshRequired() {
        return contextHolderRefreshRequired;
    }
}
