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

package org.springframework.security.providers.dao.cache;

import junit.framework.TestCase;

import org.springframework.security.GrantedAuthority;
import org.springframework.security.GrantedAuthorityImpl;

import org.springframework.security.userdetails.User;


/**
 * Tests {@link NullUserCache}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class NullUserCacheTests extends TestCase {
    //~ Constructors ===================================================================================================

    public NullUserCacheTests() {
        super();
    }

    public NullUserCacheTests(String arg0) {
        super(arg0);
    }

    //~ Methods ========================================================================================================

    private User getUser() {
        return new User("john", "password", true, true, true, true,
            new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl("ROLE_TWO")});
    }

    public static void main(String[] args) {
        junit.textui.TestRunner.run(NullUserCacheTests.class);
    }

    public final void setUp() throws Exception {
        super.setUp();
    }

    public void testCacheOperation() throws Exception {
        NullUserCache cache = new NullUserCache();
        cache.putUserInCache(getUser());
        assertNull(cache.getUserFromCache(null));
        cache.removeUserFromCache(null);
    }
}
