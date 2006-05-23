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

package org.acegisecurity.util;

import junit.framework.TestCase;

import java.util.HashMap;
import java.util.Map;


/**
 * Tests {@link PortMapperImpl}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class PortMapperImplTests extends TestCase {
    //~ Constructors ===================================================================================================

    public PortMapperImplTests() {
        super();
    }

    public PortMapperImplTests(String arg0) {
        super(arg0);
    }

    //~ Methods ========================================================================================================

    public static void main(String[] args) {
        junit.textui.TestRunner.run(PortMapperImplTests.class);
    }

    public final void setUp() throws Exception {
        super.setUp();
    }

    public void testDefaultMappingsAreKnown() throws Exception {
        PortMapperImpl portMapper = new PortMapperImpl();
        assertEquals(new Integer(80), portMapper.lookupHttpPort(new Integer(443)));
        assertEquals(new Integer(8080), portMapper.lookupHttpPort(new Integer(8443)));
        assertEquals(new Integer(443), portMapper.lookupHttpsPort(new Integer(80)));
        assertEquals(new Integer(8443), portMapper.lookupHttpsPort(new Integer(8080)));
    }

    public void testDetectsEmptyMap() throws Exception {
        PortMapperImpl portMapper = new PortMapperImpl();

        try {
            portMapper.setPortMappings(new HashMap());
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }
    }

    public void testDetectsNullMap() throws Exception {
        PortMapperImpl portMapper = new PortMapperImpl();

        try {
            portMapper.setPortMappings(null);
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }
    }

    public void testGetTranslatedPortMappings() {
        PortMapperImpl portMapper = new PortMapperImpl();
        assertEquals(2, portMapper.getTranslatedPortMappings().size());
    }

    public void testRejectsOutOfRangeMappings() {
        PortMapperImpl portMapper = new PortMapperImpl();
        Map map = new HashMap();
        map.put("79", "80559");

        try {
            portMapper.setPortMappings(map);
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }
    }

    public void testReturnsNullIfHttpPortCannotBeFound() {
        PortMapperImpl portMapper = new PortMapperImpl();
        assertTrue(portMapper.lookupHttpPort(new Integer("34343")) == null);
    }

    public void testSupportsCustomMappings() {
        PortMapperImpl portMapper = new PortMapperImpl();
        Map map = new HashMap();
        map.put("79", "442");

        portMapper.setPortMappings(map);

        assertEquals(new Integer(79), portMapper.lookupHttpPort(new Integer(442)));
        assertEquals(new Integer(442), portMapper.lookupHttpsPort(new Integer(79)));
    }
}
