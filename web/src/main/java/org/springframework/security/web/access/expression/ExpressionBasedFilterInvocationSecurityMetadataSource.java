package org.springframework.security.web.access.expression;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.ParseException;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.web.access.intercept.DefaultFilterInvocationSecurityMetadataSource;
import org.springframework.security.web.access.intercept.RequestKey;
import org.springframework.security.web.util.UrlMatcher;
import org.springframework.util.Assert;

/**
 * Expression-based <tt>FilterInvocationSecurityMetadataSource</tt>.
 *
 * @author Luke Taylor
 * @since 3.0
 */
public final class ExpressionBasedFilterInvocationSecurityMetadataSource extends DefaultFilterInvocationSecurityMetadataSource {
    private final static Log logger = LogFactory.getLog(ExpressionBasedFilterInvocationSecurityMetadataSource.class);

    public ExpressionBasedFilterInvocationSecurityMetadataSource(UrlMatcher urlMatcher,
            LinkedHashMap<RequestKey, Collection<ConfigAttribute>> requestMap, WebSecurityExpressionHandler expressionHandler) {
        super(urlMatcher, processMap(requestMap, expressionHandler.getExpressionParser()));
        Assert.notNull(expressionHandler, "A non-null SecurityExpressionHandler is required");
    }

    private static LinkedHashMap<RequestKey, Collection<ConfigAttribute>> processMap(
            LinkedHashMap<RequestKey,Collection<ConfigAttribute>> requestMap, ExpressionParser parser) {
        Assert.notNull(parser, "SecurityExpressionHandler returned a null parser object");

        LinkedHashMap<RequestKey, Collection<ConfigAttribute>> requestToExpressionAttributesMap =
            new LinkedHashMap<RequestKey, Collection<ConfigAttribute>>(requestMap);

        for (Map.Entry<RequestKey, Collection<ConfigAttribute>> entry : requestMap.entrySet()) {
            RequestKey request = entry.getKey();
            Assert.isTrue(entry.getValue().size() == 1, "Expected a single expression attribute for " + request);
            ArrayList<ConfigAttribute> attributes = new ArrayList<ConfigAttribute>(1);
            String expression = entry.getValue().toArray(new ConfigAttribute[1])[0].getAttribute();
            logger.debug("Adding web access control expression '" + expression + "', for " + request);
            try {
                attributes.add(new WebExpressionConfigAttribute(parser.parseExpression(expression)));
            } catch (ParseException e) {
                throw new IllegalArgumentException("Failed to parse expression '" + expression + "'");
            }

            requestToExpressionAttributesMap.put(request, attributes);
        }

        return requestToExpressionAttributesMap;
    }

}
