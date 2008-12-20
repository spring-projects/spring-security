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
package org.springframework.security.acls.domain;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import static org.junit.Assert.*;
import org.junit.Test;
import org.springframework.security.acls.Permission;


/**
 * Tests classes associated with Permission.
 *
 * @author Ben Alex
 * @version $Id${date}
 */
public class PermissionTests {
    private static final Log LOGGER = LogFactory.getLog(PermissionTests.class);

    //~ Methods ========================================================================================================

    @Test
    public void basePermissionTest() {
        Permission p = BasePermission.buildFromName("WRITE");
        assertNotNull(p);
    }

    @Test
    public void expectedIntegerValues() {
        assertEquals(1, BasePermission.READ.getMask());
        assertEquals(16, BasePermission.ADMINISTRATION.getMask());
        assertEquals(7,
                new CumulativePermission().set(BasePermission.READ).set(BasePermission.WRITE).set(BasePermission.CREATE)
                        .getMask());
        assertEquals(17,
                new CumulativePermission().set(BasePermission.READ).set(BasePermission.ADMINISTRATION).getMask());
    }

    @Test
    public void fromInteger() {
        Permission permission = BasePermission.buildFromMask(7);
        System.out.println("7 =  " + permission.toString());
        permission = BasePermission.buildFromMask(4);
        System.out.println("4 =  " + permission.toString());
    }

    @Test
    public void stringConversion() {
        System.out.println("R =  " + BasePermission.READ.toString());
        assertEquals("BasePermission[...............................R=1]", BasePermission.READ.toString());

        System.out.println("A =  " + BasePermission.ADMINISTRATION.toString());
        assertEquals("BasePermission[...........................A....=16]", BasePermission.ADMINISTRATION.toString());

        System.out.println("R =  " + new CumulativePermission().set(BasePermission.READ).toString());
        assertEquals("CumulativePermission[...............................R=1]",
                new CumulativePermission().set(BasePermission.READ).toString());

        System.out.println("A =  " + new CumulativePermission().set(SpecialPermission.ENTER).set(BasePermission.ADMINISTRATION).toString());
        assertEquals("CumulativePermission[..........................EA....=48]",
                new CumulativePermission().set(SpecialPermission.ENTER).set(BasePermission.ADMINISTRATION).toString());

        System.out.println("RA = "
                + new CumulativePermission().set(BasePermission.ADMINISTRATION).set(BasePermission.READ).toString());
        assertEquals("CumulativePermission[...........................A...R=17]",
                new CumulativePermission().set(BasePermission.ADMINISTRATION).set(BasePermission.READ).toString());

        System.out.println("R =  "
                + new CumulativePermission().set(BasePermission.ADMINISTRATION).set(BasePermission.READ)
                .clear(BasePermission.ADMINISTRATION).toString());
        assertEquals("CumulativePermission[...............................R=1]",
                new CumulativePermission().set(BasePermission.ADMINISTRATION).set(BasePermission.READ)
                        .clear(BasePermission.ADMINISTRATION).toString());

        System.out.println("0 =  "
                + new CumulativePermission().set(BasePermission.ADMINISTRATION).set(BasePermission.READ)
                .clear(BasePermission.ADMINISTRATION).clear(BasePermission.READ).toString());
        assertEquals("CumulativePermission[................................=0]",
                new CumulativePermission().set(BasePermission.ADMINISTRATION).set(BasePermission.READ)
                        .clear(BasePermission.ADMINISTRATION).clear(BasePermission.READ).toString());
    }
}
