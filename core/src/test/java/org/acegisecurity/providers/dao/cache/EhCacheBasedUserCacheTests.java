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

package net.sf.acegisecurity.providers.dao.cache;

import junit.framework.TestCase;

import net.sf.acegisecurity.GrantedAuthority;
import net.sf.acegisecurity.GrantedAuthorityImpl;
import net.sf.acegisecurity.providers.dao.User;


/**
 * Tests {@link EhCacheBasedUserCache}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class EhCacheBasedUserCacheTests extends TestCase {
    //~ Constructors ===========================================================

    public EhCacheBasedUserCacheTests() {
        super();
    }

    public EhCacheBasedUserCacheTests(String arg0) {
        super(arg0);
    }

    //~ Methods ================================================================

    public final void setUp() throws Exception {
        super.setUp();
    }

    public static void main(String[] args) {
        junit.textui.TestRunner.run(EhCacheBasedUserCacheTests.class);
    }

    public void testCacheOperation() throws Exception {
        EhCacheBasedUserCache cache = new EhCacheBasedUserCache();
        cache.afterPropertiesSet();

        // Check it gets stored in the cache
        cache.putUserInCache(getUser());
        assertEquals(getUser().getPassword(),
            cache.getUserFromCache(getUser().getUsername()).getPassword());

        // Check it gets removed from the cache
        cache.removeUserFromCache(getUser());
        assertNull(cache.getUserFromCache(getUser().getUsername()));

        // Check it doesn't return values for null or unknown users
        assertNull(cache.getUserFromCache(null));
        assertNull(cache.getUserFromCache("UNKNOWN_USER"));

        cache.destroy();
    }

    public void testGettersSetters() {
        EhCacheBasedUserCache cache = new EhCacheBasedUserCache();
        cache.setMinutesToIdle(15);
        assertEquals(15, cache.getMinutesToIdle());
    }

    private User getUser() {
        return new User("john", "password", true,
            new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl(
                    "ROLE_TWO")});
    }
}
