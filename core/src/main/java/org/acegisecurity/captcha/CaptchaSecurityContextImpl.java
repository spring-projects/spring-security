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

import net.sf.acegisecurity.context.SecurityContextImpl;


/**
 * Default CaptchaSecurityContext implementation
 *
 * @author mag
 */
public class CaptchaSecurityContextImpl extends SecurityContextImpl
    implements CaptchaSecurityContext {
    //~ Instance fields ========================================================

    private boolean human;
    private int humanRestrictedResourcesRequestsCount;
    private long lastPassedCaptchaDate;

    //~ Constructors ===========================================================

    /**
     *
     */
    public CaptchaSecurityContextImpl() {
        super();
        human = false;
        lastPassedCaptchaDate = 0;
        humanRestrictedResourcesRequestsCount = 0;
    }

    //~ Methods ================================================================

    /**
     * reset the lastPassedCaptchaDate and count.
     */
    public void setHuman() {
        this.human = true;
        this.lastPassedCaptchaDate = System.currentTimeMillis();
        this.humanRestrictedResourcesRequestsCount = 0;
    }

    /*
     * (non-Javadoc)
     *
     * @see net.sf.acegisecurity.context.CaptchaSecurityContext#isHuman()
     */
    public boolean isHuman() {
        return human;
    }

    /*
     * (non-Javadoc)
     *
     * @see net.sf.acegisecurity.context.CaptchaSecurityContext#getHumanRestrictedResourcesRequestsCount()
     */
    public int getHumanRestrictedResourcesRequestsCount() {
        return humanRestrictedResourcesRequestsCount;
    }

    /*
     * (non-Javadoc)
     *
     * @see net.sf.acegisecurity.context.CaptchaSecurityContext#getLastPassedCaptchaDateInMillis()
     */
    public long getLastPassedCaptchaDateInMillis() {
        return lastPassedCaptchaDate;
    }

    /**
     * Method to increment the human Restricted Resrouces Requests Count;
     */
    public void incrementHumanRestrictedRessoucesRequestsCount() {
        humanRestrictedResourcesRequestsCount++;
    }
}
