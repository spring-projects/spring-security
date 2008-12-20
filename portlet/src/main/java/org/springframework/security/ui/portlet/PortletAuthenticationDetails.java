package org.springframework.security.ui.portlet;

import java.io.Serializable;
import java.util.Map;

import javax.portlet.PortletRequest;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

public class PortletAuthenticationDetails implements Serializable {    
    //~ Instance fields ================================================================================================
    protected final Log logger = LogFactory.getLog(PortletAuthenticationDetails.class);
    protected Map userInfo;

    //~ Constructors ===================================================================================================
        
    public PortletAuthenticationDetails(PortletRequest request) {
        try {
            userInfo = (Map)request.getAttribute(PortletRequest.USER_INFO);
        } catch (Exception e) {
            logger.warn("unable to retrieve USER_INFO map from portlet request", e);
        }
    }

    public Map getUserInfo() {
        return userInfo;
    }
    
    public String toString() {
        return "User info: " + userInfo;
    }
}
