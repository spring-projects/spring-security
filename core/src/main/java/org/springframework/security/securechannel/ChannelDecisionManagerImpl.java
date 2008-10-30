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

package org.springframework.security.securechannel;

import org.springframework.security.ConfigAttribute;

import org.springframework.security.intercept.web.FilterInvocation;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.util.Assert;

import java.io.IOException;

import java.util.Iterator;
import java.util.List;

import javax.servlet.ServletException;


/**
 * Implementation of {@link ChannelDecisionManager}.
 * <p>
 * Iterates through each configured {@link ChannelProcessor}. If a <code>ChannelProcessor</code> has any issue with the
 * security of the request, it should cause a redirect, exception or whatever other action is appropriate for the
 * <code>ChannelProcessor</code> implementation.
 * <p>
 * Once any response is committed (ie a redirect is written to the response object), the
 * <code>ChannelDecisionManagerImpl</code> will not iterate through any further <code>ChannelProcessor</code>s.
 * <p>
 * The attribute "ANY_CHANNEL" if applied to a particular URL, the iteration through the channel processors will be
 * skipped (see SEC-494, SEC-335).
 *
 * @author Ben Alex
 * @version $Id$
 */
public class ChannelDecisionManagerImpl implements ChannelDecisionManager, InitializingBean {

    public static final String ANY_CHANNEL = "ANY_CHANNEL";

    //~ Instance fields ================================================================================================

    private List channelProcessors;

    //~ Methods ========================================================================================================

    public void afterPropertiesSet() throws Exception {
        checkIfValidList(this.channelProcessors);
    }

    private void checkIfValidList(List listToCheck) {
        Assert.notEmpty(listToCheck, "A list of ChannelProcessors is required");
    }

    public void decide(FilterInvocation invocation, List<ConfigAttribute> config)
            throws IOException, ServletException {

        Iterator attrs = config.iterator();

        while (attrs.hasNext()) {
            ConfigAttribute attribute = (ConfigAttribute) attrs.next();
            if (ANY_CHANNEL.equals(attribute.getAttribute())) {
                return;
            }
        }

        Iterator iter = this.channelProcessors.iterator();

        while (iter.hasNext()) {
            ChannelProcessor processor = (ChannelProcessor) iter.next();

            processor.decide(invocation, config);

            if (invocation.getResponse().isCommitted()) {
                break;
            }
        }
    }

    protected List getChannelProcessors() {
        return this.channelProcessors;
    }

    public void setChannelProcessors(List newList) {
        checkIfValidList(newList);

        Iterator iter = newList.iterator();

        while (iter.hasNext()) {
            Object currentObject = iter.next();
            Assert.isInstanceOf(ChannelProcessor.class, currentObject, "ChannelProcessor " +
                    currentObject.getClass().getName() + " must implement ChannelProcessor");
        }

        this.channelProcessors = newList;
    }

    public boolean supports(ConfigAttribute attribute) {
        if (ANY_CHANNEL.equals(attribute.getAttribute())) {
            return true;
        }

        Iterator iter = this.channelProcessors.iterator();

        while (iter.hasNext()) {
            ChannelProcessor processor = (ChannelProcessor) iter.next();

            if (processor.supports(attribute)) {
                return true;
            }
        }

        return false;
    }
}
