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

package net.sf.acegisecurity.providers.dao.memory;

import junit.framework.TestCase;

import net.sf.acegisecurity.providers.dao.UsernameNotFoundException;


/**
 * Tests {@link InMemoryDaoImpl}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class InMemoryDaoTests extends TestCase {
    //~ Constructors ===========================================================

    public InMemoryDaoTests() {
        super();
    }

    public InMemoryDaoTests(String arg0) {
        super(arg0);
    }

    //~ Methods ================================================================

    public final void setUp() throws Exception {
        super.setUp();
    }

    public static void main(String[] args) {
        junit.textui.TestRunner.run(InMemoryDaoTests.class);
    }

    public void testLookupFails() throws Exception {
        InMemoryDaoImpl dao = new InMemoryDaoImpl();
        dao.setUserMap(makeUserMap());
        dao.afterPropertiesSet();

        try {
            dao.loadUserByUsername("UNKNOWN_USER");
            fail("Should have thrown UsernameNotFoundException");
        } catch (UsernameNotFoundException expected) {
            assertTrue(true);
        }
    }

    public void testLookupSuccess() throws Exception {
        InMemoryDaoImpl dao = new InMemoryDaoImpl();
        dao.setUserMap(makeUserMap());
        dao.afterPropertiesSet();
        assertEquals("koala", dao.loadUserByUsername("marissa").getPassword());
        assertEquals("wombat", dao.loadUserByUsername("scott").getPassword());
    }

    public void testLookupSuccessWithMixedeCase() throws Exception {
        InMemoryDaoImpl dao = new InMemoryDaoImpl();
        dao.setUserMap(makeUserMap());
        dao.afterPropertiesSet();
        assertEquals("koala", dao.loadUserByUsername("MaRiSSA").getPassword());
        assertEquals("wombat", dao.loadUserByUsername("ScOTt").getPassword());
    }

    public void testStartupFailsIfUserMapNotSet() throws Exception {
        InMemoryDaoImpl dao = new InMemoryDaoImpl();

        try {
            dao.afterPropertiesSet();
            fail("Shoudl have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }
    }

    public void testStartupFailsIfUserMapSetToNull() throws Exception {
        InMemoryDaoImpl dao = new InMemoryDaoImpl();
        dao.setUserMap(null);

        try {
            dao.afterPropertiesSet();
            fail("Shoudl have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }
    }

    public void testStartupSuccessIfUserMapSet() throws Exception {
        InMemoryDaoImpl dao = new InMemoryDaoImpl();
        dao.setUserMap(makeUserMap());
        dao.afterPropertiesSet();
        assertEquals(2, dao.getUserMap().getUserCount());
    }

    private UserMap makeUserMap() {
        UserMapEditor editor = new UserMapEditor();
        editor.setAsText(
            "marissa=koala,ROLE_ONE,ROLE_TWO,enabled\r\nscott=wombat,ROLE_ONE,ROLE_TWO,enabled");

        return (UserMap) editor.getValue();
    }
}
