/* Copyright 2004 Acegi Technology Pty Limited
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

package net.sf.acegisecurity.runas;

import net.sf.acegisecurity.Authentication;
import net.sf.acegisecurity.ConfigAttribute;
import net.sf.acegisecurity.ConfigAttributeDefinition;
import net.sf.acegisecurity.GrantedAuthority;
import net.sf.acegisecurity.GrantedAuthorityImpl;
import net.sf.acegisecurity.RunAsManager;

import org.aopalliance.intercept.MethodInvocation;

import org.springframework.beans.factory.InitializingBean;

import java.util.Iterator;
import java.util.List;
import java.util.Vector;


/**
 * Basic concrete implementation of a {@link RunAsManager}.
 * 
 * <p>
 * Is activated if any {@link ConfigAttribute#getAttribute()} is prefixed  with
 * <Code>RUN_AS_</code>. If found, it generates a new  {@link RunAsUserToken}
 * containing the same principal, credentials and granted authorities as the
 * original {@link Authentication} object, along with {@link
 * GrantedAuthorityImpl}s for each <code>RUN_AS_</code> indicated. The created
 * <code>GrantedAuthorityImpl</code>s will be prefixed with <code>ROLE_</code>
 * and then the remainder of the <code>RUN_AS_</code> keyword. For example,
 * <code>RUN_AS_FOO</code> will result in the creation of a granted authority
 * of <code>ROLE_RUN_AS_FOO</code>.
 * </p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public class RunAsManagerImpl implements RunAsManager, InitializingBean {
    //~ Instance fields ========================================================

    private String key;

    //~ Methods ================================================================

    public void setKey(String key) {
        this.key = key;
    }

    public String getKey() {
        return key;
    }

    public void afterPropertiesSet() throws Exception {
        if (key == null) {
            throw new IllegalArgumentException(
                "A Key is required and should match that configured for the RunAsImplAuthenticationProvider");
        }
    }

    public Authentication buildRunAs(Authentication authentication,
        MethodInvocation invocation, ConfigAttributeDefinition config) {
        List newAuthorities = new Vector();
        Iterator iter = config.getConfigAttributes();

        while (iter.hasNext()) {
            ConfigAttribute attribute = (ConfigAttribute) iter.next();

            if (this.supports(attribute)) {
                GrantedAuthorityImpl extraAuthority = new GrantedAuthorityImpl(
                        "ROLE_" + attribute.getAttribute());
                newAuthorities.add(extraAuthority);
            }
        }

        if (newAuthorities.size() == 0) {
            return null;
        } else {
            for (int i = 0; i < authentication.getAuthorities().length; i++) {
                newAuthorities.add(authentication.getAuthorities()[i]);
            }

            GrantedAuthority[] resultType = {new GrantedAuthorityImpl("holder")};
            GrantedAuthority[] newAuthoritiesAsArray = (GrantedAuthority[]) newAuthorities
                .toArray(resultType);

            return new RunAsUserToken(this.key, authentication.getPrincipal(),
                authentication.getCredentials(), newAuthoritiesAsArray,
                authentication.getClass());
        }
    }

    public boolean supports(ConfigAttribute attribute) {
        if ((attribute.getAttribute() != null)
            && attribute.getAttribute().startsWith("RUN_AS_")) {
            return true;
        } else {
            return false;
        }
    }
}
