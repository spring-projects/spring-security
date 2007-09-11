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

/**
 * <p>return false if ny CaptchaChannelProcessorTemplate mapped urls has been requested more than thresold and
 * humanity is false; <br>
 * Default keyword : REQUIRES_CAPTCHA_ONCE_ABOVE_THRESOLD_REQUESTS</p>
 *
 * @author Marc-Antoine Garrigue
 * @version $Id$
 */
public class TestOnceAfterMaxRequestsCaptchaChannelProcessor extends CaptchaChannelProcessorTemplate {
    //~ Static fields/initializers =====================================================================================

    public static final String DEFAULT_KEYWORD = "REQUIRES_CAPTCHA_ONCE_ABOVE_THRESOLD_REQUESTS";

    //~ Constructors ===================================================================================================

    public TestOnceAfterMaxRequestsCaptchaChannelProcessor() {
        this.setKeyword(DEFAULT_KEYWORD);
    }

    //~ Methods ========================================================================================================

    boolean isContextValidConcerningHumanity(CaptchaSecurityContext context) {
        if (context.isHuman() || (context.getHumanRestrictedResourcesRequestsCount() < getThreshold())) {
            logger.debug("context is valid concerning humanity or request count < thresold");

            return true;
        } else {
            logger.debug("context is not valid concerning humanity and request count > thresold");

            return false;
        }
    }
}
