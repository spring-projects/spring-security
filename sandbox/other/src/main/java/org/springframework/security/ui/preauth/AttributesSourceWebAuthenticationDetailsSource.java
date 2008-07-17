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
package org.springframework.security.ui.preauth;

import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.ui.AuthenticationDetailsSource;
import org.springframework.security.ui.WebAuthenticationDetailsSource;
import org.springframework.util.Assert;

/**
 * Implementation of {@link AuthenticationDetailsSource} which builds the details object from an
 * <tt>HttpServletRequest</tt> object.
 * <p>
 * Uses <code>attributesSource</code> to obtain attributes from the request. Adds obtained
 * attributes to created details object. The details object must be an instance of
 * <tt>AuthenticationDetailsImpl</tt>, which has additional <tt>attributes</tt> property.
 * 
 * @author Valery Tydykov
 */
public class AttributesSourceWebAuthenticationDetailsSource extends WebAuthenticationDetailsSource
        implements InitializingBean {

    public AttributesSourceWebAuthenticationDetailsSource() {
        super();
        setClazz(AuthenticationDetailsImpl.class);
    }

    private AttributesSource attributesSource;

    /*
     * (non-Javadoc)
     * 
     * @see org.springframework.security.ui.WebAuthenticationDetailsSource#buildDetails(java.lang.Object)
     */
    public Object buildDetails(Object context) {
        // build AuthenticationDetailsImpl object
        Object result = super.buildDetails(context);

        Assert.isInstanceOf(HttpServletRequest.class, context);
        HttpServletRequest request = (HttpServletRequest) context;

        // extract attributes from the request
        Map attributes = this.getAttributesSource().obtainAttributes(request);

        // add additional attributes to the AuthenticationDetailsImpl object
        AuthenticationDetailsImpl authenticationDetails;
        {
            Assert.isInstanceOf(AuthenticationDetailsImpl.class, result);
            authenticationDetails = (AuthenticationDetailsImpl) result;
            // add attributes from the AttributesSource to the AuthenticationDetailsImpl object
            authenticationDetails.getAttributes().putAll(attributes);
        }

        return authenticationDetails;
    }

    /**
     * @return the attributesSource
     */
    public AttributesSource getAttributesSource() {
        return this.attributesSource;
    }

    /**
     * @param attributesSource the attributesSource to set
     */
    public void setAttributesSource(AttributesSource attributesSource) {
        Assert.notNull(attributesSource, "attributesSource must not be null");
        this.attributesSource = attributesSource;
    }

    /*
     * (non-Javadoc)
     * 
     * @see org.springframework.beans.factory.InitializingBean#afterPropertiesSet()
     */
    public void afterPropertiesSet() throws Exception {
        Assert.notNull(this.attributesSource, "attributesSource must be set");
    }
}
