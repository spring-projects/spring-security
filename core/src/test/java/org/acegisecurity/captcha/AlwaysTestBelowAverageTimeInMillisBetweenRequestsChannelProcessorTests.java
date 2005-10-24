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

import junit.framework.TestCase;


/**
 * DOCUMENT ME!
 *
 * @author $author$
 * @version $Revision$
 */
public class AlwaysTestBelowAverageTimeInMillisBetweenRequestsChannelProcessorTests
    extends TestCase {
    //~ Instance fields ========================================================

    AlwaysTestBelowAverageTimeInMillisBetweenRequestsChannelProcessor alwaysTestBelowAverageTimeInMillisBetweenRequestsChannelProcessor;

    //~ Methods ================================================================

    public void testEqualsThresold() {
        CaptchaSecurityContext context = new CaptchaSecurityContextImpl();
        alwaysTestBelowAverageTimeInMillisBetweenRequestsChannelProcessor
        .setThresold(100);

        context.setHuman();

        long now = System.currentTimeMillis();

        while ((System.currentTimeMillis() - now) <= 100) {
            assertTrue(alwaysTestBelowAverageTimeInMillisBetweenRequestsChannelProcessor
                .isContextValidConcerningHumanity(context));
        }

        context.incrementHumanRestrictedRessoucesRequestsCount();
        assertTrue(alwaysTestBelowAverageTimeInMillisBetweenRequestsChannelProcessor
            .isContextValidConcerningHumanity(context));

        context.setHuman();
        context.incrementHumanRestrictedRessoucesRequestsCount();
        assertFalse(alwaysTestBelowAverageTimeInMillisBetweenRequestsChannelProcessor
            .isContextValidConcerningHumanity(context));

        alwaysTestBelowAverageTimeInMillisBetweenRequestsChannelProcessor
        .setThresold(0);
        context.setHuman();
        context.incrementHumanRestrictedRessoucesRequestsCount();
        assertFalse(alwaysTestBelowAverageTimeInMillisBetweenRequestsChannelProcessor
            .isContextValidConcerningHumanity(context));
        alwaysTestBelowAverageTimeInMillisBetweenRequestsChannelProcessor
        .setThresold(0);
    }

    public void testIsContextValidConcerningHumanity()
        throws Exception {
        CaptchaSecurityContext context = new CaptchaSecurityContextImpl();
        alwaysTestBelowAverageTimeInMillisBetweenRequestsChannelProcessor
        .setThresold(10);
        context.setHuman();

        while ((System.currentTimeMillis()
            - context.getLastPassedCaptchaDateInMillis()) < (10 * alwaysTestBelowAverageTimeInMillisBetweenRequestsChannelProcessor
            .getThresold())) {
            assertTrue(alwaysTestBelowAverageTimeInMillisBetweenRequestsChannelProcessor
                .isContextValidConcerningHumanity(context));
        }
    }

    public void testNewContext() {
        CaptchaSecurityContext context = new CaptchaSecurityContextImpl();
        assertFalse(alwaysTestBelowAverageTimeInMillisBetweenRequestsChannelProcessor
            .isContextValidConcerningHumanity(context));

        context.setHuman();
        assertTrue(alwaysTestBelowAverageTimeInMillisBetweenRequestsChannelProcessor
            .isContextValidConcerningHumanity(context));
    }

    public void testShouldPassAbove() {
        CaptchaSecurityContext context = new CaptchaSecurityContextImpl();

        context.setHuman();

        int i = 0;

        while ((System.currentTimeMillis()
            - context.getLastPassedCaptchaDateInMillis()) < (100 * alwaysTestBelowAverageTimeInMillisBetweenRequestsChannelProcessor
            .getThresold())) {
            System.out.println((System.currentTimeMillis()
                - context.getLastPassedCaptchaDateInMillis()));

            context.incrementHumanRestrictedRessoucesRequestsCount();
            i++;

            while ((System.currentTimeMillis()
                - context.getLastPassedCaptchaDateInMillis()) < (alwaysTestBelowAverageTimeInMillisBetweenRequestsChannelProcessor
                .getThresold() * i)) {}

            System.out.println((System.currentTimeMillis()
                - context.getLastPassedCaptchaDateInMillis()));

            assertTrue(alwaysTestBelowAverageTimeInMillisBetweenRequestsChannelProcessor
                .isContextValidConcerningHumanity(context));
        }
    }

    protected void setUp() throws Exception {
        super.setUp();
        alwaysTestBelowAverageTimeInMillisBetweenRequestsChannelProcessor = new AlwaysTestBelowAverageTimeInMillisBetweenRequestsChannelProcessor();
    }
}
