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

import org.acegisecurity.captcha.AlwaysTestAfterMaxRequestsCaptchaChannelProcessor;


/**
 * DOCUMENT ME!
 *
 * @author $author$
 * @version $Revision$
 */
public class AlwaysTestAfterMaxRequestsCaptchaChannelProcessorTests extends TestCase {
    //~ Instance fields ================================================================================================

    AlwaysTestAfterMaxRequestsCaptchaChannelProcessor alwaysTestAfterMaxRequestsCaptchaChannelProcessor;

    //~ Methods ========================================================================================================

    protected void setUp() throws Exception {
        super.setUp();
        alwaysTestAfterMaxRequestsCaptchaChannelProcessor = new AlwaysTestAfterMaxRequestsCaptchaChannelProcessor();
    }

    public void testIsContextValidConcerningHumanity()
        throws Exception {
        alwaysTestAfterMaxRequestsCaptchaChannelProcessor.setThresold(1);

        CaptchaSecurityContextImpl context = new CaptchaSecurityContextImpl();
        assertTrue(alwaysTestAfterMaxRequestsCaptchaChannelProcessor.isContextValidConcerningHumanity(context));

        context.incrementHumanRestrictedRessoucesRequestsCount();

        alwaysTestAfterMaxRequestsCaptchaChannelProcessor.setThresold(-1);
        assertFalse(alwaysTestAfterMaxRequestsCaptchaChannelProcessor.isContextValidConcerningHumanity(context));

        alwaysTestAfterMaxRequestsCaptchaChannelProcessor.setThresold(3);
        assertTrue(alwaysTestAfterMaxRequestsCaptchaChannelProcessor.isContextValidConcerningHumanity(context));
        context.incrementHumanRestrictedRessoucesRequestsCount();
        assertTrue(alwaysTestAfterMaxRequestsCaptchaChannelProcessor.isContextValidConcerningHumanity(context));
        context.incrementHumanRestrictedRessoucesRequestsCount();
        assertFalse(alwaysTestAfterMaxRequestsCaptchaChannelProcessor.isContextValidConcerningHumanity(context));
    }

    public void testNewContext() {
        CaptchaSecurityContextImpl context = new CaptchaSecurityContextImpl();

        assertFalse(alwaysTestAfterMaxRequestsCaptchaChannelProcessor.isContextValidConcerningHumanity(context));
        alwaysTestAfterMaxRequestsCaptchaChannelProcessor.setThresold(1);
        assertTrue(alwaysTestAfterMaxRequestsCaptchaChannelProcessor.isContextValidConcerningHumanity(context));
    }
}
