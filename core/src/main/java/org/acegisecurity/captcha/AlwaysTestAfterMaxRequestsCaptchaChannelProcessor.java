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
package org.acegisecurity.captcha;

/**
 * <p>return false if ny CaptchaChannelProcessorTemplate of mapped urls has been requested more than thresold; <br>
 * Default keyword : REQUIRES_CAPTCHA_ABOVE_THRESOLD_REQUESTS</p>
 *
 * @author Marc-Antoine Garrigue
 * @version $Id$
 */
public class AlwaysTestAfterMaxRequestsCaptchaChannelProcessor extends CaptchaChannelProcessorTemplate {
    //~ Static fields/initializers =====================================================================================

    /** Keyword for this channelProcessor */
    public static final String DEFAULT_KEYWORD = "REQUIRES_CAPTCHA_ABOVE_THRESHOLD_REQUESTS";

    //~ Constructors ===================================================================================================

    /**
     * Constructor
     */
    public AlwaysTestAfterMaxRequestsCaptchaChannelProcessor() {
        this.setKeyword(DEFAULT_KEYWORD);
    }

    //~ Methods ========================================================================================================

    /**
     * Verify whether the context is valid concerning humanity
     *
     * @param context
     *
     * @return true if valid, false otherwise
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
