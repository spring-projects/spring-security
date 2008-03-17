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

/*
 * Copyright (c) 2005 Your Corporation. All Rights Reserved.
 */
package org.springframework.security.captcha;

/**
 * Return false if the number of requests for captcha protcted URLs for the user
 * exceeds the threshold value. 
 * 
 * <br/>
 * Default keyword : <tt>REQUIRES_CAPTCHA_ABOVE_THRESHOLD_REQUESTS</tt>
 *
 * @author Marc-Antoine Garrigue
 * @version $Id$
 */
public class AlwaysTestAfterMaxRequestsCaptchaChannelProcessor extends CaptchaChannelProcessorTemplate {
    //~ Static fields/initializers =====================================================================================

    /** Keyword for this channelProcessor */
    public static final String DEFAULT_KEYWORD = "REQUIRES_CAPTCHA_ABOVE_THRESHOLD_REQUESTS";

    //~ Constructors ===================================================================================================

    public AlwaysTestAfterMaxRequestsCaptchaChannelProcessor() {
        this.setKeyword(DEFAULT_KEYWORD);
    }

    //~ Methods ========================================================================================================

    /**
     *
     * @return false if the number of requests for captcha protected URLs exceeds the threshold.
     */
    boolean isContextValidConcerningHumanity(CaptchaSecurityContext context) {
        if (context.getHumanRestrictedResourcesRequestsCount() < getThreshold()) {
            logger.debug("context is valid : request count < thresold");

            return true;
        } else {
            logger.debug("context is not valid : request count > thresold");

            return false;
        }
    }
}
