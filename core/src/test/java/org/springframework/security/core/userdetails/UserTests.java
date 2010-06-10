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

package org.springframework.security.core.userdetails;

import static org.junit.Assert.*;

import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.junit.Test;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.GrantedAuthorityImpl;


/**
 * Tests {@link User}.
 *
 * @author Ben Alex
 */
public class UserTests {
    private static final List<GrantedAuthority> ROLE_12 = AuthorityUtils.createAuthorityList("ROLE_ONE","ROLE_TWO");
    //~ Methods ========================================================================================================

    @Test
    public void equalsReturnsTrueIfUsernamesAreTheSame() {
        User user1 = new User("rod", "koala", true, true, true, true, ROLE_12);

        assertFalse(user1.equals(null));
        assertFalse(user1.equals("A STRING"));
        assertTrue(user1.equals(user1));
        assertTrue(user1.equals(new User("rod", "notthesame", true, true, true, true, ROLE_12)));
    }

    @Test
    public void hashLookupOnlyDependsOnUsername() throws Exception {
        User user1 = new User("rod", "koala", true, true, true, true, ROLE_12);
        Set<UserDetails> users = new HashSet<UserDetails>();
        users.add(user1);

        assertTrue(users.contains(new User("rod", "koala", true, true, true, true, ROLE_12)));
        assertTrue(users.contains(new User("rod", "anotherpass", false, false, false, false, AuthorityUtils.createAuthorityList("ROLE_X"))));
        assertFalse(users.contains(new User("bod", "koala", true, true, true, true, ROLE_12)));
    }

    @Test
    public void testNoArgConstructorDoesntExist() {
        Class<User> clazz = User.class;

        try {
            clazz.getDeclaredConstructor((Class[]) null);
            fail("Should have thrown NoSuchMethodException");
        } catch (NoSuchMethodException expected) {
        }
    }

    @Test
    public void testNullValuesRejected() throws Exception {
        try {
            new User(null, "koala", true, true, true, true,ROLE_12);
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
        }

        try {
            new User("rod", null, true, true, true, true, ROLE_12);
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
        }

        try {
            List<GrantedAuthority> auths = AuthorityUtils.createAuthorityList("ROLE_ONE");
            auths.add(null);
            new User("rod", "koala", true, true, true, true, auths);
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
        }
    }

    @Test
    public void testNullWithinGrantedAuthorityElementIsRejected() throws Exception {
        try {
            List<GrantedAuthority> auths = AuthorityUtils.createAuthorityList("ROLE_ONE");
            auths.add(null);
            auths.add(new GrantedAuthorityImpl("ROLE_THREE"));
            new User(null, "koala", true, true, true, true, auths);
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
        }
    }

    @Test
    public void testUserGettersSetter() throws Exception {
        UserDetails user = new User("rod", "koala", true, true, true, true,
                AuthorityUtils.createAuthorityList("ROLE_TWO","ROLE_ONE"));
        assertEquals("rod", user.getUsername());
        assertEquals("koala", user.getPassword());
        assertTrue(user.isEnabled());
        assertTrue(AuthorityUtils.authorityListToSet(user.getAuthorities()).contains("ROLE_ONE"));
        assertTrue(AuthorityUtils.authorityListToSet(user.getAuthorities()).contains("ROLE_TWO"));
        assertTrue(user.toString().indexOf("rod") != -1);
    }

    @Test
    public void enabledFlagIsFalseForDisabledAccount() throws Exception {
        UserDetails user = new User("rod", "koala", false, true, true, true, ROLE_12);
        assertFalse(user.isEnabled());
    }

    @Test
    public void useIsSerializable() throws Exception {
        UserDetails user = new User("rod", "koala", false, true, true, true, ROLE_12);
        // Serialize to a byte array
        ByteArrayOutputStream bos = new ByteArrayOutputStream() ;
        ObjectOutputStream out = new ObjectOutputStream(bos) ;
        out.writeObject(user);
        out.close();
    }
}
