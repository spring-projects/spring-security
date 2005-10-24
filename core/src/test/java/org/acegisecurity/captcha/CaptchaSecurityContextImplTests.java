/* Copyright 2004, 2005 Acegi Technology Pty Limited
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

package net.sf.acegisecurity.captcha;

import net.sf.acegisecurity.context.SecurityContextImplTests;


/**
 * Tests {@link CaptchaSecurityContextImpl}.
 *
 * @author marc antoine Garrigue
 * @version $Id$
 */
public class CaptchaSecurityContextImplTests extends SecurityContextImplTests {
    //~ Methods ================================================================

    public void testDefaultValues() {
        CaptchaSecurityContext context = new CaptchaSecurityContextImpl();
        assertEquals("should not be human", false, context.isHuman());
        assertEquals("should be 0", 0,
            context.getLastPassedCaptchaDateInMillis());
        assertEquals("should be 0", 0,
            context.getHumanRestrictedResourcesRequestsCount());
    }

    public void testIncrementRequests() {
        CaptchaSecurityContext context = new CaptchaSecurityContextImpl();
        context.setHuman();
        assertEquals("should be human", true, context.isHuman());
        assertEquals("should be 0", 0,
            context.getHumanRestrictedResourcesRequestsCount());
        context.incrementHumanRestrictedRessoucesRequestsCount();
        assertEquals("should be 1", 1,
            context.getHumanRestrictedResourcesRequestsCount());
    }

    public void testResetHuman() {
        CaptchaSecurityContext context = new CaptchaSecurityContextImpl();
        context.setHuman();
        assertEquals("should be human", true, context.isHuman());
        assertEquals("should be 0", 0,
            context.getHumanRestrictedResourcesRequestsCount());
        context.incrementHumanRestrictedRessoucesRequestsCount();
        assertEquals("should be 1", 1,
            context.getHumanRestrictedResourcesRequestsCount());

        long now = System.currentTimeMillis();
        context.setHuman();
        assertEquals("should be 0", 0,
            context.getHumanRestrictedResourcesRequestsCount());
        assertTrue("should be more than 0",
            (context.getLastPassedCaptchaDateInMillis() - now) >= 0);
        assertTrue("should be less than 0,1 seconde",
            (context.getLastPassedCaptchaDateInMillis() - now) < 100);
    }

    public void testSetHuman() {
        CaptchaSecurityContext context = new CaptchaSecurityContextImpl();
        long now = System.currentTimeMillis();
        context.setHuman();
        assertEquals("should be human", true, context.isHuman());
        assertTrue("should be more than 0",
            (context.getLastPassedCaptchaDateInMillis() - now) >= 0);
        assertTrue("should be less than 0,1 seconde",
            (context.getLastPassedCaptchaDateInMillis() - now) < 100);
        assertEquals("should be 0", 0,
            context.getHumanRestrictedResourcesRequestsCount());
    }
}
