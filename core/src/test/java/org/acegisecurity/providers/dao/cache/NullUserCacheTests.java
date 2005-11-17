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

package org.acegisecurity.providers.dao.cache;

import junit.framework.TestCase;

import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.GrantedAuthorityImpl;
import org.acegisecurity.providers.dao.User;


/**
 * Tests {@link NullUserCache}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class NullUserCacheTests extends TestCase {
    //~ Constructors ===========================================================

    public NullUserCacheTests() {
        super();
    }

    public NullUserCacheTests(String arg0) {
        super(arg0);
    }

    //~ Methods ================================================================

    public final void setUp() throws Exception {
        super.setUp();
    }

    public static void main(String[] args) {
        junit.textui.TestRunner.run(NullUserCacheTests.class);
    }

    public void testCacheOperation() throws Exception {
        NullUserCache cache = new NullUserCache();
        cache.putUserInCache(getUser());
        assertNull(cache.getUserFromCache(null));
        cache.removeUserFromCache(null);
    }

    private User getUser() {
        return new User("john", "password", true, true, true, true,
            new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl(
                    "ROLE_TWO")});
    }
}
