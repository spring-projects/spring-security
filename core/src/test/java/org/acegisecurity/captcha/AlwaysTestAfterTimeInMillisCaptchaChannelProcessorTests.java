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

package org.acegisecurity.captcha;

import junit.framework.*;

import org.acegisecurity.captcha.AlwaysTestAfterTimeInMillisCaptchaChannelProcessor;


/**
 * WARNING! This test class make some assumptions concerning the compute speed! For example the two following
 * instructions should be computed in the same millis or the test is not valid.<pre><code>context.setHuman();
 * assertFalse(alwaysTestAfterTimeInMillisCaptchaChannelProcessor.isContextValidConcerningHumanity(context));
 * </code></pre>This should be the case for most environements unless
 *  <ul>
 *      <li>you run it on a good old TRS-80</li>
 *      <li>you start M$office during this test ;)</li>
 *  </ul>
 */
public class AlwaysTestAfterTimeInMillisCaptchaChannelProcessorTests extends TestCase {
    //~ Instance fields ================================================================================================

    AlwaysTestAfterTimeInMillisCaptchaChannelProcessor alwaysTestAfterTimeInMillisCaptchaChannelProcessor;

    //~ Methods ========================================================================================================

    protected void setUp() throws Exception {
        super.setUp();
        alwaysTestAfterTimeInMillisCaptchaChannelProcessor = new AlwaysTestAfterTimeInMillisCaptchaChannelProcessor();
    }

    public void testEqualsThresold() {
        CaptchaSecurityContext context = new CaptchaSecurityContextImpl();
        assertFalse(alwaysTestAfterTimeInMillisCaptchaChannelProcessor.isContextValidConcerningHumanity(context));

        //the two following instructions should be computed or the test is not valid (never fails). This should be the case
        // for most environements unless if you run it on a good old TRS-80 (thanks mom).
        context.setHuman();
        assertFalse(alwaysTestAfterTimeInMillisCaptchaChannelProcessor.isContextValidConcerningHumanity(context));
    }

    public void testIsContextValidConcerningHumanity()
        throws Exception {
        CaptchaSecurityContext context = new CaptchaSecurityContextImpl();
        alwaysTestAfterTimeInMillisCaptchaChannelProcessor.setThresold(100);
        context.setHuman();

        while ((System.currentTimeMillis() - context.getLastPassedCaptchaDateInMillis()) < alwaysTestAfterTimeInMillisCaptchaChannelProcessor
            .getThresold()) {
            assertTrue(alwaysTestAfterTimeInMillisCaptchaChannelProcessor.isContextValidConcerningHumanity(context));
            context.incrementHumanRestrictedRessoucesRequestsCount();

            long now = System.currentTimeMillis();

            while ((System.currentTimeMillis() - now) < 1) {}

            ;
        }

        assertFalse(alwaysTestAfterTimeInMillisCaptchaChannelProcessor.isContextValidConcerningHumanity(context));
    }

    public void testNewContext() {
        CaptchaSecurityContext context = new CaptchaSecurityContextImpl();

        //alwaysTestAfterTimeInMillisCaptchaChannelProcessor.setThresold(10);
        assertFalse(alwaysTestAfterTimeInMillisCaptchaChannelProcessor.isContextValidConcerningHumanity(context));
    }
}
