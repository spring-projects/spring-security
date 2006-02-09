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

import org.acegisecurity.providers.AbstractAuthenticationToken;


/**
 * Simple holder that indicates the {@link MockRunAsManager} returned a
 * different <Code>Authentication</code> object.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class MockRunAsAuthenticationToken extends AbstractAuthenticationToken {
    //~ Constructors ===========================================================

    public MockRunAsAuthenticationToken() {
        super(null);
    }

    //~ Methods ================================================================

    public Object getCredentials() {
        return null;
    }

    public Object getPrincipal() {
        return null;
    }
}
