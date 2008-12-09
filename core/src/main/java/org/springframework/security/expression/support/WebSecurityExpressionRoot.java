package org.springframework.security.expression.support;

import java.net.InetAddress;
import java.net.UnknownHostException;

import org.springframework.security.Authentication;
import org.springframework.security.intercept.web.FilterInvocation;
import org.springframework.util.StringUtils;

/**
 *
 * @author Luke Taylor
 * @version $Id$
 * @since 2.5
 */
class WebSecurityExpressionRoot extends SecurityExpressionRoot {
    private FilterInvocation filterInvocation;

    WebSecurityExpressionRoot(Authentication a, FilterInvocation fi) {
        super(a);
        this.filterInvocation = fi;
    }

    public boolean hasIpAddress(String ipAddress) {
        byte[] mask = null;

        if (ipAddress.indexOf('/') > 0) {
            String[] addressAndMask = StringUtils.split(ipAddress, "/");
            ipAddress = addressAndMask[0];
            try {
                mask = InetAddress.getByName(addressAndMask[1]).getAddress();
            } catch (UnknownHostException e) {
                throw new IllegalArgumentException("Failed to parse mask" + addressAndMask[1], e);
            }
        }

        try {
            InetAddress requiredAddress = InetAddress.getByName(ipAddress);
            InetAddress remoteAddress = InetAddress.getByName(filterInvocation.getHttpRequest().getRemoteAddr());

            if (mask == null) {
                return remoteAddress.equals(requiredAddress);
            } else {

            }
//            byte[] remoteAddress = InetAddress.getByName(filterInvocation.getHttpRequest().getRemoteAddr()).getAddress();
        } catch (UnknownHostException e) {
            throw new IllegalArgumentException("Failed to parse " + ipAddress, e);
        }

        return false;
    }
}
