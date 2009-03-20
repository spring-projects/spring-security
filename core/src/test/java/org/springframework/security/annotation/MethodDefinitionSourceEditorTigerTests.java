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

package org.springframework.security.annotation;

import static org.junit.Assert.assertEquals;

import java.util.List;

import org.junit.Before;
import org.junit.Test;
import org.springframework.security.ConfigAttribute;
import org.springframework.security.SecurityConfig;
import org.springframework.security.annotation.test.Entity;
import org.springframework.security.annotation.test.PersonServiceImpl;
import org.springframework.security.annotation.test.Service;
import org.springframework.security.intercept.method.MapBasedMethodSecurityMetadataSource;
import org.springframework.security.intercept.method.MethodSecurityMetadataSourceEditor;
import org.springframework.security.intercept.method.MockMethodInvocation;


/**
 * Extra tests to demonstrate generics behaviour with <code>MapBasedMethodDefinitionSource</code>.
 *
 * @author Ben Alex
 * @version $Id$
 */
@SuppressWarnings("deprecation")
public class MethodDefinitionSourceEditorTigerTests {
    private MockMethodInvocation makeUpper;
    private MockMethodInvocation makeLower;

    @Before
    public void createMethodInvocations() throws Exception {
        makeUpper = new MockMethodInvocation(new PersonServiceImpl(), Service.class,"makeUpperCase", Entity.class);
        makeLower = new MockMethodInvocation(new PersonServiceImpl(), Service.class,"makeLowerCase", Entity.class);
    }

    @Test
    public void testConcreteClassInvocations() throws Exception {
        MethodSecurityMetadataSourceEditor editor = new MethodSecurityMetadataSourceEditor();
        editor.setAsText(
                "org.springframework.security.annotation.test.Service.makeLower*=ROLE_FROM_INTERFACE\r\n" +
                "org.springframework.security.annotation.test.Service.makeUpper*=ROLE_FROM_INTERFACE\r\n" +
                "org.springframework.security.annotation.test.ServiceImpl.makeUpper*=ROLE_FROM_IMPLEMENTATION");

        MapBasedMethodSecurityMetadataSource map = (MapBasedMethodSecurityMetadataSource) editor.getValue();
        assertEquals(3, map.getMethodMapSize());

        List<? extends ConfigAttribute> returnedMakeLower = map.getAttributes(makeLower);
        List<? extends ConfigAttribute> expectedMakeLower = SecurityConfig.createList("ROLE_FROM_INTERFACE");
        assertEquals(expectedMakeLower, returnedMakeLower);

        List<? extends ConfigAttribute> returnedMakeUpper = map.getAttributes(makeUpper);
        List<? extends ConfigAttribute> expectedMakeUpper = SecurityConfig.createList(new String[]{"ROLE_FROM_IMPLEMENTATION"});
        assertEquals(expectedMakeUpper, returnedMakeUpper);
    }

    @Test
    public void testBridgeMethodResolution() throws Exception {
        MethodSecurityMetadataSourceEditor editor = new MethodSecurityMetadataSourceEditor();
        editor.setAsText(
                "org.springframework.security.annotation.test.PersonService.makeUpper*=ROLE_FROM_INTERFACE\r\n" +
                "org.springframework.security.annotation.test.ServiceImpl.makeUpper*=ROLE_FROM_ABSTRACT\r\n" +
                "org.springframework.security.annotation.test.PersonServiceImpl.makeUpper*=ROLE_FROM_PSI");

        MapBasedMethodSecurityMetadataSource map = (MapBasedMethodSecurityMetadataSource) editor.getValue();
        assertEquals(3, map.getMethodMapSize());

        List<? extends ConfigAttribute> returnedMakeUpper = map.getAttributes(makeUpper);
        List<? extends ConfigAttribute> expectedMakeUpper = SecurityConfig.createList("ROLE_FROM_PSI");
        assertEquals(expectedMakeUpper, returnedMakeUpper);
    }

}
