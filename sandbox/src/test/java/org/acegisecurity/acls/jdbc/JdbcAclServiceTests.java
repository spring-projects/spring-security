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

package org.acegisecurity.acls.jdbc;

import org.acegisecurity.acls.Acl;
import org.acegisecurity.acls.objectidentity.ObjectIdentity;
import org.acegisecurity.acls.objectidentity.ObjectIdentityImpl;

import org.springframework.test.AbstractDependencyInjectionSpringContextTests;

import java.util.Iterator;
import java.util.Map;


/**
 * DOCUMENT ME!
 *
 * @author $author$
 * @version $Revision$
  */
public class JdbcAclServiceTests extends AbstractDependencyInjectionSpringContextTests {
    //~ Instance fields ================================================================================================

    private JdbcAclService jdbcAclService;

    //~ Methods ========================================================================================================

    protected String[] getConfigLocations() {
        return new String[] {"classpath:org/acegisecurity/acls/jdbc/applicationContext-test.xml"};
    }

    public void setJdbcAclService(JdbcAclService jdbcAclService) {
        this.jdbcAclService = jdbcAclService;
    }

    public void testStub() {
        ObjectIdentity id1 = new ObjectIdentityImpl("sample.contact.Contact", new Long(1));
        ObjectIdentity id2 = new ObjectIdentityImpl("sample.contact.Contact", new Long(2));
        ObjectIdentity id3 = new ObjectIdentityImpl("sample.contact.Contact", new Long(3));
        ObjectIdentity id4 = new ObjectIdentityImpl("sample.contact.Contact", new Long(4));
        ObjectIdentity id5 = new ObjectIdentityImpl("sample.contact.Contact", new Long(5));
        ObjectIdentity id6 = new ObjectIdentityImpl("sample.contact.Contact", new Long(6));
        Map map = jdbcAclService.readAclsById(new ObjectIdentity[] {id1, id2, id3, id4, id5, id6});
        Iterator iterator = map.keySet().iterator();

        while (iterator.hasNext()) {
            ObjectIdentity identity = (ObjectIdentity) iterator.next();
            assertEquals(identity, ((Acl) map.get(identity)).getObjectIdentity());
            System.out.println(map.get(identity));
        }
    }
}
