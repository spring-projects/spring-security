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

package org.springframework.security.intercept.method;

import java.lang.reflect.Method;

import junit.framework.Assert;

import org.junit.Test;
import org.springframework.security.ConfigAttributeDefinition;
import org.springframework.security.ITargetObject;


/**
 * Tests {@link MethodDefinitionAttributes}.
 *
 * @author Cameron Braid
 * @author Ben Alex
 * @version $Id$
 */
public class MethodDefinitionAttributesTests {

	private MethodDefinitionAttributes build() {
    	MethodDefinitionAttributes mda = new MethodDefinitionAttributes();
    	mda.setAttributes(new MockAttributes());
    	return mda;
    }
    
    @Test
    public void testMethodsReturned() throws Exception {
        Class clazz = ITargetObject.class;
        Method method = clazz.getMethod("countLength", new Class[] {String.class});
    	ConfigAttributeDefinition result = build().findAttributes(method, ITargetObject.class);
    	Assert.assertEquals(1, result.getConfigAttributes().size());
    }

    @Test
    public void testClassesReturned() throws Exception {
        Class clazz = ITargetObject.class;
    	ConfigAttributeDefinition result = build().findAttributes(ITargetObject.class);
    	Assert.assertEquals(1, result.getConfigAttributes().size());
    }

}
