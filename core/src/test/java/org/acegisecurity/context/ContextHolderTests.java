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

package net.sf.acegisecurity.context;

import junit.framework.TestCase;


/**
 * Tests {@link ContextHolder}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class ContextHolderTests extends TestCase {
    //~ Constructors ===========================================================

    public ContextHolderTests() {
        super();
    }

    public ContextHolderTests(String arg0) {
        super(arg0);
    }

    //~ Methods ================================================================

    public final void setUp() throws Exception {
        super.setUp();
    }

    public static void main(String[] args) {
        junit.textui.TestRunner.run(ContextHolderTests.class);
    }

    public void testContextHolderGetterSetter() {
        assertEquals(null, ContextHolder.getContext());

        MockContext context = new MockContext();
        context.setColour("red");
        ContextHolder.setContext(context);

        MockContext offContext = (MockContext) ContextHolder.getContext();
        assertEquals("red", offContext.getColour());
    }

    //~ Inner Classes ==========================================================

    private class MockContext implements Context {
        private String colour;

        public void setColour(String colour) {
            this.colour = colour;
        }

        public String getColour() {
            return colour;
        }

        public void validate() throws ContextInvalidException {
            return;
        }
    }
}
