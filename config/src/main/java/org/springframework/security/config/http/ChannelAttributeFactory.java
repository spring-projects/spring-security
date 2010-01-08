package org.springframework.security.config.http;

import java.util.List;

import org.springframework.beans.factory.BeanCreationException;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.web.access.channel.ChannelDecisionManagerImpl;

/**
 * Used as a factory bean to create config attribute values for the <tt>requires-channel</tt> attribute.
 *
 * @author Luke Taylor
 * @since 3.0
 */
public class ChannelAttributeFactory {
    private static final String OPT_REQUIRES_HTTP = "http";
    private static final String OPT_REQUIRES_HTTPS = "https";
    private static final String OPT_ANY_CHANNEL = "any";

    public static final List<ConfigAttribute> createChannelAttributes(String requiredChannel) {
        String channelConfigAttribute = null;

        if (requiredChannel.equals(OPT_REQUIRES_HTTPS)) {
            channelConfigAttribute = "REQUIRES_SECURE_CHANNEL";
        } else if (requiredChannel.equals(OPT_REQUIRES_HTTP)) {
            channelConfigAttribute = "REQUIRES_INSECURE_CHANNEL";
        } else if (requiredChannel.equals(OPT_ANY_CHANNEL)) {
            channelConfigAttribute = ChannelDecisionManagerImpl.ANY_CHANNEL;
        } else {
            throw new BeanCreationException("Unknown channel attribute " + requiredChannel);
        }

        return SecurityConfig.createList(channelConfigAttribute);
    }
}
