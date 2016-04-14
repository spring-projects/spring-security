package org.springframework.security.cas.jackson2;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import org.jasig.cas.client.proxy.ProxyRetriever;

import java.util.Map;

/**
 * @author Jitendra Singh
 */
@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS, include = JsonTypeInfo.As.PROPERTY)
public class AttributePrincipalImplMixin {

    @JsonCreator
    public AttributePrincipalImplMixin(@JsonProperty("name") String name, @JsonProperty("attributes") Map<String, Object> attributes,
                                       @JsonProperty("proxyGrantingTicket") String proxyGrantingTicket,
                                       @JsonProperty("proxyRetriever") ProxyRetriever proxyRetriever) {
    }
}
