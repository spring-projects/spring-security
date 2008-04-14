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

package org.springframework.security.acl.basic;

import org.springframework.security.Authentication;
import org.springframework.security.GrantedAuthority;

import org.springframework.security.acl.AclEntry;

import org.springframework.security.userdetails.UserDetails;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.util.List;
import java.util.Vector;


/**
 * Simple implementation of {@link EffectiveAclsResolver}.<P>This implementation does not need to understand the
 * "recipient" types presented in a <code>BasicAclEntry</code> because it merely delegates to the detected {@link
 * Authentication#getPrincipal()} or {@link Authentication#getAuthorities()}. The principal object or granted
 * authorities object has its <code>Object.equals(recipient)</code> method called to make the decision as to whether
 * the recipient in the <code>BasicAclEntry</code> is the same as the principal or granted authority.</p>
 *  <P>This class should prove an adequate ACLs resolver if you're using standard Spring Security classes. This is
 * because the typical <code>Authentication</code> token is <code>UsernamePasswordAuthenticationToken</code>, which
 * for its <code>principal</code> is usually a <code>String</code>. The <code>GrantedAuthorityImpl</code> is typically
 * used for granted authorities, which tests for equality based on a <code>String</code>. This means
 * <code>BasicAclDao</code>s simply need to return a <code>String</code> to represent the recipient. If you use
 * non-<code>String</code> objects, you will probably require an alternative <code>EffectiveAclsResolver</code>.</p>
 *
 * @author Ben Alex
 * @version $Id$
 * @deprecated Use new spring-security-acl module instead
 */
public class GrantedAuthorityEffectiveAclsResolver implements EffectiveAclsResolver {
    //~ Static fields/initializers =====================================================================================

    private static final Log logger = LogFactory.getLog(GrantedAuthorityEffectiveAclsResolver.class);

    //~ Methods ========================================================================================================

    public AclEntry[] resolveEffectiveAcls(AclEntry[] allAcls, Authentication filteredBy) {
        if ((allAcls == null) || (allAcls.length == 0)) {
            return null;
        }

        List list = new Vector();

        if (logger.isDebugEnabled()) {
            logger.debug("Locating AclEntry[]s (from set of " + ((allAcls == null) ? 0 : allAcls.length)
                + ") that apply to Authentication: " + filteredBy);
        }

        for (int i = 0; i < allAcls.length; i++) {
            if (!(allAcls[i] instanceof BasicAclEntry)) {
                continue;
            }

            Object recipient = ((BasicAclEntry) allAcls[i]).getRecipient();

            // Allow the Authentication's getPrincipal to decide whether
            // the presented recipient is "equal" (allows BasicAclDaos to
            // return Strings rather than proper objects in simple cases)
            if (filteredBy.getPrincipal().equals(recipient)) {
                if (logger.isDebugEnabled()) {
                    logger.debug("Principal matches AclEntry recipient: " + recipient);
                }

                list.add(allAcls[i]);
            } else if (filteredBy.getPrincipal() instanceof UserDetails
                && ((UserDetails) filteredBy.getPrincipal()).getUsername().equals(recipient)) {
                if (logger.isDebugEnabled()) {
                    logger.debug("Principal (from UserDetails) matches AclEntry recipient: " + recipient);
                }

                list.add(allAcls[i]);
            } else {
                // No direct match against principal; try each authority.
                // As with the principal, allow each of the Authentication's
                // granted authorities to decide whether the presented
                // recipient is "equal"
                GrantedAuthority[] authorities = filteredBy.getAuthorities();

                if ((authorities == null) || (authorities.length == 0)) {
                    if (logger.isDebugEnabled()) {
                        logger.debug("Did not match principal and there are no granted authorities, "
                                + "so cannot compare with recipient: " + recipient);
                    }

                    continue;
                }

                for (int k = 0; k < authorities.length; k++) {
                    if (authorities[k].equals(recipient)) {
                        if (logger.isDebugEnabled()) {
                            logger.debug("GrantedAuthority: " + authorities[k] + " matches recipient: " + recipient);
                        }

                        list.add(allAcls[i]);
                    }
                }
            }
        }

        // return null if appropriate (as per interface contract)
        if (list.size() > 0) {
            if (logger.isDebugEnabled()) {
                logger.debug("Returning effective AclEntry array with " + list.size() + " elements");
            }

            return (BasicAclEntry[]) list.toArray(new BasicAclEntry[] {});
        } else {
            if (logger.isDebugEnabled()) {
                logger.debug("Returning null AclEntry array as zero effective AclEntrys found");
            }

            return null;
        }
    }
}
