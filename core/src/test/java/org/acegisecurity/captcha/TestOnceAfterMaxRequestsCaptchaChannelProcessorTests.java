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

package org.acegisecurity.captcha;

import junit.framework.*;

import org.acegisecurity.captcha.TestOnceAfterMaxRequestsCaptchaChannelProcessor;


/**
 * DOCUMENT ME!
 *
 * @author $author$
 * @version $Revision$
 */
public class TestOnceAfterMaxRequestsCaptchaChannelProcessorTests
    extends TestCase {
    //~ Instance fields ========================================================

    TestOnceAfterMaxRequestsCaptchaChannelProcessor testOnceAfterMaxRequestsCaptchaChannelProcessor;

    //~ Methods ================================================================

    public void testIsContextValidConcerningHumanity()
        throws Exception {
        testOnceAfterMaxRequestsCaptchaChannelProcessor.setThresold(1);

        CaptchaSecurityContextImpl context = new CaptchaSecurityContextImpl();
        assertTrue(testOnceAfterMaxRequestsCaptchaChannelProcessor
            .isContextValidConcerningHumanity(context));

        context.incrementHumanRestrictedRessoucesRequestsCount();

        testOnceAfterMaxRequestsCaptchaChannelProcessor.setThresold(-1);
        assertFalse(testOnceAfterMaxRequestsCaptchaChannelProcessor
            .isContextValidConcerningHumanity(context));

        testOnceAfterMaxRequestsCaptchaChannelProcessor.setThresold(3);
        assertTrue(testOnceAfterMaxRequestsCaptchaChannelProcessor
            .isContextValidConcerningHumanity(context));
        context.incrementHumanRestrictedRessoucesRequestsCount();
        assertTrue(testOnceAfterMaxRequestsCaptchaChannelProcessor
            .isContextValidConcerningHumanity(context));
        context.incrementHumanRestrictedRessoucesRequestsCount();
        assertFalse(testOnceAfterMaxRequestsCaptchaChannelProcessor
            .isContextValidConcerningHumanity(context));
        context.setHuman();

        for (int i = 0;
            i < (2 * testOnceAfterMaxRequestsCaptchaChannelProcessor
            .getThresold()); i++) {
            assertTrue(testOnceAfterMaxRequestsCaptchaChannelProcessor
                .isContextValidConcerningHumanity(context));
        }
    }

    public void testNewContext() {
        CaptchaSecurityContextImpl context = new CaptchaSecurityContextImpl();

        assertFalse(testOnceAfterMaxRequestsCaptchaChannelProcessor
            .isContextValidConcerningHumanity(context));
        testOnceAfterMaxRequestsCaptchaChannelProcessor.setThresold(1);
        assertTrue(testOnceAfterMaxRequestsCaptchaChannelProcessor
            .isContextValidConcerningHumanity(context));
    }

    protected void setUp() throws Exception {
        super.setUp();
        testOnceAfterMaxRequestsCaptchaChannelProcessor = new TestOnceAfterMaxRequestsCaptchaChannelProcessor();
    }
}
