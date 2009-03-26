package org.springframework.security.web.expression;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Arrays;

import org.springframework.security.Authentication;
import org.springframework.security.expression.support.SecurityExpressionRoot;
import org.springframework.security.web.intercept.FilterInvocation;
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

    /**
     * Takes a specific IP address or a range using the IP/Netmask (e.g. 192.168.1.0/24 or 202.24.0.0/14).
     *
     * @param ipAddress the address or range of addresses from which the request must come.
     * @return true if the IP address of the current request is in the required range.
     */
    public boolean hasIpAddress(String ipAddress) {
        int nMaskBits = 0;

        if (ipAddress.indexOf('/') > 0) {
            String[] addressAndMask = StringUtils.split(ipAddress, "/");
            ipAddress = addressAndMask[0];
            nMaskBits = Integer.parseInt(addressAndMask[1]);
        }

        InetAddress requiredAddress = parseAddress(ipAddress);
        InetAddress remoteAddress = parseAddress(filterInvocation.getHttpRequest().getRemoteAddr());

        if (!requiredAddress.getClass().equals(remoteAddress.getClass())) {
            throw new IllegalArgumentException("IP Address in expression must be the same type as " +
                    "version returned by request");
        }

        if (nMaskBits == 0) {
            return remoteAddress.equals(requiredAddress);
        }

        byte[] remAddr = remoteAddress.getAddress();
        byte[] reqAddr = requiredAddress.getAddress();

        int oddBits = nMaskBits % 8;
        int nMaskBytes = nMaskBits/8 + (oddBits == 0 ? 0 : 1);
        byte[] mask = new byte[nMaskBytes];

        Arrays.fill(mask, 0, oddBits == 0 ? mask.length : mask.length - 1, (byte)0xFF);

        if (oddBits != 0) {
            int finalByte = (1 << oddBits) - 1;
            finalByte <<= 8-oddBits;
            mask[mask.length - 1] = (byte) finalByte;
        }

 //       System.out.println("Mask is " + new sun.misc.HexDumpEncoder().encode(mask));

        for (int i=0; i < mask.length; i++) {
            if ((remAddr[i] & mask[i]) != (reqAddr[i] & mask[i])) {
                return false;
            }
        }

        return true;
    }

    private InetAddress parseAddress(String address) {
        try {
            return InetAddress.getByName(address);
        } catch (UnknownHostException e) {
            throw new IllegalArgumentException("Failed to parse address" + address, e);
        }
    }
}
