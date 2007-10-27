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

package org.springframework.security.captcha;

import junit.framework.*;

import org.springframework.security.captcha.TestOnceAfterMaxRequestsCaptchaChannelProcessor;


/**
 * DOCUMENT ME!
 *
 * @author $author$
 * @version $Revision: 2142 $
 */
public class TestOnceAfterMaxRequestsCaptchaChannelProcessorTests extends TestCase {
    //~ Instance fields ================================================================================================

    TestOnceAfterMaxRequestsCaptchaChannelProcessor testOnceAfterMaxRequestsCaptchaChannelProcessor;

    //~ Methods ========================================================================================================

    protected void setUp() throws Exception {
        super.setUp();
        testOnceAfterMaxRequestsCaptchaChannelProcessor = new TestOnceAfterMaxRequestsCaptchaChannelProcessor();
    }

    public void testIsContextValidConcerningHumanity()
        throws Exception {
        testOnceAfterMaxRequestsCaptchaChannelProcessor.setThreshold(1);

        CaptchaSecurityContextImpl context = new CaptchaSecurityContextImpl();
        assertTrue(testOnceAfterMaxRequestsCaptchaChannelProcessor.isContextValidConcerningHumanity(context));

        context.incrementHumanRestrictedResourcesRequestsCount();

        testOnceAfterMaxRequestsCaptchaChannelProcessor.setThreshold(-1);
        assertFalse(testOnceAfterMaxRequestsCaptchaChannelProcessor.isContextValidConcerningHumanity(context));

        testOnceAfterMaxRequestsCaptchaChannelProcessor.setThreshold(3);
        assertTrue(testOnceAfterMaxRequestsCaptchaChannelProcessor.isContextValidConcerningHumanity(context));
        context.incrementHumanRestrictedResourcesRequestsCount();
        assertTrue(testOnceAfterMaxRequestsCaptchaChannelProcessor.isContextValidConcerningHumanity(context));
        context.incrementHumanRestrictedResourcesRequestsCount();
        assertFalse(testOnceAfterMaxRequestsCaptchaChannelProcessor.isContextValidConcerningHumanity(context));
        context.setHuman();

        for (int i = 0; i < (2 * testOnceAfterMaxRequestsCaptchaChannelProcessor.getThreshold()); i++) {
            assertTrue(testOnceAfterMaxRequestsCaptchaChannelProcessor.isContextValidConcerningHumanity(context));
        }
    }

    public void testNewContext() {
        CaptchaSecurityContextImpl context = new CaptchaSecurityContextImpl();

        assertFalse(testOnceAfterMaxRequestsCaptchaChannelProcessor.isContextValidConcerningHumanity(context));
        testOnceAfterMaxRequestsCaptchaChannelProcessor.setThreshold(1);
        assertTrue(testOnceAfterMaxRequestsCaptchaChannelProcessor.isContextValidConcerningHumanity(context));
    }
}
