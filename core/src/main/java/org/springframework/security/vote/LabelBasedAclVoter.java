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
package org.springframework.security.vote;

import org.springframework.security.Authentication;
import org.springframework.security.ConfigAttribute;
import org.springframework.security.ConfigAttributeDefinition;

import org.aopalliance.intercept.MethodInvocation;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.util.Assert;

import java.util.Iterator;
import java.util.List;
import java.util.Vector;
import java.util.Map;


/**
 * <p>This Acl voter will evaluate methods based on labels applied to incoming arguments. It will only check
 * methods that have been properly tagged in the MethodSecurityInterceptor with the value stored in
 * <tt>attributeIndicatingLabeledOperation</tt>. If a method has been tagged, then it examines each argument, and if the
 * argument implements {@link LabeledData}, then it will asses if the user's list of granted authorities matches.
 * </p>
 *
 * <p>By default, if none of the arguments are labeled, then the access will be granted. This can be overridden by
 * setting <tt>allowAccessIfNoAttributesAreLabeled</tt> to false in the Spring context file.</p>
 *
 * <p>In many situations, different values are linked together to define a common label, it is necessary to
 * define a map in the application context that links user-assigned label access to domain object labels. This is done
 * by setting up the <tt>labelMap</tt> in the application context.</p>
 *
 * @author Greg Turnquist
 * @version $Id$
 *
 * @see org.springframework.security.intercept.method.aopalliance.MethodSecurityInterceptor
 * @deprecated Use new spring-security-acl module instead
 */
public class LabelBasedAclVoter extends AbstractAclVoter {
    //~ Static fields/initializers =====================================================================================

    private static final Log logger = LogFactory.getLog(LabelBasedAclVoter.class);

    //~ Instance fields ================================================================================================

    private Map labelMap = null;
    private String attributeIndicatingLabeledOperation = null;
    private boolean allowAccessIfNoAttributesAreLabeled = true;

    //~ Methods ========================================================================================================

    /**
     * Set whether or not to allow the user to run methods in which none of the incoming arguments are labeled.
     *
     * <p>Default value: <b>true, users can run such methods.</b></p>
     *
     * @param allowAccessIfNoAttributesAreLabeled boolean
     */
    public void setAllowAccessIfNoAttributesAreLabeled(boolean allowAccessIfNoAttributesAreLabeled) {
        this.allowAccessIfNoAttributesAreLabeled = allowAccessIfNoAttributesAreLabeled;
    }

    /**
     * Each method intended for evaluation by this voter must include this tag name in the definition of the
     * MethodSecurityInterceptor, indicating if this voter should evaluate the arguments and compare them against the
     * label map.
     *
     * @param attributeIndicatingLabeledOperation string
     */
    public void setAttributeIndicatingLabeledOperation(String attributeIndicatingLabeledOperation) {
        this.attributeIndicatingLabeledOperation = attributeIndicatingLabeledOperation;
    }

    /**
     * Set the map that correlate a user's assigned label against domain object values that are considered data
     * labels. An example application context configuration of a <tt>labelMap</tt>:
     *
     * <pre>
     * &lt;bean id="accessDecisionManager" class="org.springframework.security.vote.UnanimousBased"&gt;
     *     &lt;property name="allowIfAllAbstainDecisions"&gt;&lt;value&gt;false&lt;/value&gt;&lt;/property&gt;
     *     &lt;property name="decisionVoters"&gt;
     *       &lt;list&gt;
     *         &lt;bean class="org.springframework.security.vote.RoleVoter"/&gt;
     *         &lt;bean class="org.springframework.security.vote.LabelBasedAclVoter"&gt;
     *           &lt;property name="attributeIndicatingLabeledOperation"&gt;
     *             &lt;value&gt;LABELED_OPERATION&lt;/value&gt;
     *           &lt;/property&gt;
     *           &lt;property name="labelMap"&gt;
     *             &lt;map&gt;
     *               &lt;entry key="DATA_LABEL_BLUE"&gt;
     *                 &lt;list&gt;
     *                   &lt;value&gt;blue&lt;/value&gt;
     *                   &lt;value&gt;indigo&lt;/value&gt;
     *                   &lt;value&gt;purple&lt;/value&gt;
     *                 &lt;/list&gt;
     *               &lt;/entry&gt;
     *               &lt;entry key="LABEL_ORANGE"&gt;
     *                 &lt;list&gt;
     *                   &lt;value&gt;orange&lt;/value&gt;
     *                   &lt;value&gt;sunshine&lt;/value&gt;
     *                   &lt;value&gt;amber&lt;/value&gt;
     *                 &lt;/list&gt;
     *               &lt;/entry&gt;
     *               &lt;entry key="LABEL_ADMIN"&gt;
     *                 &lt;list&gt;
     *                   &lt;value&gt;blue&lt;/value&gt;
     *                   &lt;value&gt;indigo&lt;/value&gt;
     *                   &lt;value&gt;purple&lt;/value&gt;
     *                   &lt;value&gt;orange&lt;/value&gt;
     *                   &lt;value&gt;sunshine&lt;/value&gt;
     *                   &lt;value&gt;amber&lt;/value&gt;
     *                 &lt;/list&gt;
     *               &lt;/entry&gt;
     *             &lt;/map&gt;
     *           &lt;/property&gt;
     *         &lt;/bean&gt;
     *       &lt;/list&gt;
     *     &lt;/property&gt;
     *   &lt;/bean&gt;
     * </pre>
     *
     * @param labelMap a map structured as in the above example.
     *
     */
    public void setLabelMap(Map labelMap) {
        this.labelMap = labelMap;
    }

    /**
     * This acl voter will only evaluate labeled methods if they are marked in the security interceptor's
     * configuration with the attribute stored in attributeIndicatingLabeledOperation.
     *
     * @param attribute DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     *
     * @see org.springframework.security.vote.AbstractAclVoter
     * @see org.springframework.security.intercept.method.aopalliance.MethodSecurityInterceptor
     */
    public boolean supports(ConfigAttribute attribute) {
        if (attribute.getAttribute().equals(attributeIndicatingLabeledOperation)) {
            logger.debug(attribute + " is supported.");

            return true;
        }

        if (logger.isDebugEnabled()) {
            logger.debug(attribute + " is unsupported.");
        }

        return false;
    }

    /**
     * Vote on whether or not the user has all the labels necessary to match the method argument's labeled
     * data.
     *
     * @param authentication DOCUMENT ME!
     * @param object DOCUMENT ME!
     * @param config DOCUMENT ME!
     *
     * @return ACCESS_ABSTAIN, ACCESS_GRANTED, or ACCESS_DENIED.
     */
    public int vote(Authentication authentication, Object object, ConfigAttributeDefinition config) {
        int result = ACCESS_ABSTAIN;

        if (logger.isDebugEnabled()) {
            logger.debug("==========================================================");
        }

        if (this.supports((ConfigAttribute) config.getConfigAttributes().iterator().next())) {
            result = ACCESS_DENIED;

            /* Parse out the user's labels by examining the security context, and checking
             * for matches against the label map.
             */
            List userLabels = new Vector();

            for (int i = 0; i < authentication.getAuthorities().length; i++) {
                if (labelMap.containsKey(authentication.getAuthorities()[i].getAuthority())) {
                    String userLabel = authentication.getAuthorities()[i].getAuthority();
                    userLabels.add(userLabel);
                    logger.debug("Adding " + userLabel + " to <<<" + authentication.getName()
                        + "'s>>> authorized label list");
                }
            }

            MethodInvocation invocation = (MethodInvocation) object;

            int matches = 0;
            int misses = 0;
            int labeledArguments = 0;

            for (int j = 0; j < invocation.getArguments().length; j++) {
                if (invocation.getArguments()[j] instanceof LabeledData) {
                    labeledArguments++;

                    boolean matched = false;

                    String argumentDataLabel = ((LabeledData) invocation.getArguments()[j]).getLabel();
                    logger.debug("Argument[" + j + "/" + invocation.getArguments()[j].getClass().getName()
                        + "] has a data label of " + argumentDataLabel);

                    List validDataLabels = new Vector();

                    for (int i = 0; i < userLabels.size(); i++) {
                        validDataLabels.addAll((List) labelMap.get(userLabels.get(i)));
                    }

                    logger.debug("The valid labels for user label " + userLabels + " are " + validDataLabels);

                    Iterator dataLabelIter = validDataLabels.iterator();

                    while (dataLabelIter.hasNext()) {
                        String validDataLabel = (String) dataLabelIter.next();

                        if (argumentDataLabel.equals(validDataLabel)) {
                            logger.debug(userLabels + " maps to " + validDataLabel + " which matches the argument");
                            matched = true;
                        }
                    }

                    if (matched) {
                        logger.debug("We have a match!");
                        matches++;
                    } else {
                        logger.debug("We have a miss!");
                        misses++;
                    }
                }
            }
            Assert.isTrue((matches + misses) == labeledArguments,
                "The matches (" + matches + ") and misses (" + misses + " ) don't add up (" + labeledArguments + ")");

            logger.debug("We have " + matches + " matches and " + misses + " misses and " + labeledArguments
                + " labeled arguments.");

            /* The result has already been set to ACCESS_DENIED. Only if there is a proper match of
             * labels will this be overturned. However, if none of the attributes are actually labeled,
             * the result is dependent on allowAccessIfNoAttributesAreLabeled.
             */
            if ((matches > 0) && (misses == 0)) {
                result = ACCESS_GRANTED;
            } else if (labeledArguments == 0) {
                if (allowAccessIfNoAttributesAreLabeled) {
                    result = ACCESS_GRANTED;
                } else {
                    result = ACCESS_DENIED;
                }
            }
        }

        if (logger.isDebugEnabled()) {
            switch (result) {
            case ACCESS_GRANTED:
                logger.debug("===== Access is granted =====");
                break;

            case ACCESS_DENIED:
                logger.debug("===== Access is denied =====");
                break;

            case ACCESS_ABSTAIN:
                logger.debug("===== Abstaining =====");
                break;
            }
        }

        return result;
    }
}
