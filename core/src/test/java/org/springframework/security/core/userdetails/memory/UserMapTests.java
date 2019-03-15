/* Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.core.userdetails.memory;

import static org.junit.Assert.*;

import org.junit.Test;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;


/**
 * Tests {@link UserMap}.
 *
 * @author Ben Alex
 */
@SuppressWarnings("deprecation")
public class UserMapTests {
    @Test
    public void testAddAndRetrieveUser() {
        UserDetails rod = new User("rod", "koala", true, true, true, true,
                AuthorityUtils.createAuthorityList("ROLE_ONE","ROLE_TWO"));
        UserDetails scott = new User("scott", "wombat", true, true, true, true,
                AuthorityUtils.createAuthorityList("ROLE_ONE","ROLE_THREE"));
        UserDetails peter = new User("peter", "opal", true, true, true, true,
                AuthorityUtils.createAuthorityList("ROLE_ONE","ROLE_FOUR"));
        UserMap map = new UserMap();
        map.addUser(rod);
        map.addUser(scott);
        map.addUser(peter);
        assertEquals(3, map.getUserCount());

        assertEquals(rod, map.getUser("rod"));
        assertEquals(scott, map.getUser("scott"));
        assertEquals(peter, map.getUser("peter"));
    }

    @Test
    public void nullUserCannotBeAdded() {
        UserMap map = new UserMap();
        assertEquals(0, map.getUserCount());

        try {
            map.addUser(null);
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }
    }

    @Test
    public void unknownUserIsNotRetrieved() {
        UserDetails rod = new User("rod", "koala", true, true, true, true,
                AuthorityUtils.createAuthorityList("ROLE_ONE","ROLE_TWO"));
        UserMap map = new UserMap();
        assertEquals(0, map.getUserCount());
        map.addUser(rod);
        assertEquals(1, map.getUserCount());

        try {
            map.getUser("scott");
            fail("Should have thrown UsernameNotFoundException");
        } catch (UsernameNotFoundException expected) {
            assertTrue(true);
        }
    }
}
