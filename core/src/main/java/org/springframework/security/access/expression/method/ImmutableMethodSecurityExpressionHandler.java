/*
 * Copyright 2002-2012 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.access.expression.method;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.expression.EvaluationContext;
import org.springframework.expression.Expression;
import org.springframework.security.access.PermissionCacheOptimizer;
import org.springframework.security.access.expression.ExpressionUtils;

import java.util.*;


/**
 * An implementation of {@code MethodSecurityExpressionHandler} that supports immutable {@code List}s and immutable {@code Set}s.
 * <p>
 * A single instance should usually be shared amongst the beans that require expression support.
 *
 * @author Mattias Severson
 * @since 3.2
 */
public class ImmutableMethodSecurityExpressionHandler extends DefaultMethodSecurityExpressionHandler implements MethodSecurityExpressionHandler {

    protected final Log logger = LogFactory.getLog(getClass());

    private PermissionCacheOptimizer permissionCacheOptimizer = null;

    /**
     * Filters the {@code filterTarget} object (which must be either a collection or an array), by evaluating the
     * supplied expression.
     * <p>
     * If a {@code Collection} is used, the original instance will be modified to contain the elements for which
     * the permission expression evaluates to {@code true}. For an array, a new array instance will be returned.
     */
    @SuppressWarnings("unchecked")
    public Object filter(Object filterTarget, Expression filterExpression, EvaluationContext ctx) {
        List retainList;

        if (filterTarget instanceof List) {
            retainList = filterCollection((List)filterTarget, filterExpression, ctx);
            return Collections.unmodifiableList(retainList);
        } else if (filterTarget instanceof SortedSet) {
            SortedSet filterSet = (SortedSet) filterTarget;
            SortedSet retainSet = new TreeSet(filterSet.comparator());
            retainList = filterCollection(filterSet, filterExpression, ctx);
            retainSet.addAll(retainList);
            return Collections.unmodifiableSortedSet(retainSet);
        } else if (filterTarget instanceof Set) {
            retainList = filterCollection((Set)filterTarget, filterExpression, ctx);
            return Collections.unmodifiableSet(new LinkedHashSet(retainList));
        } else {
            return super.filter(filterTarget, filterExpression, ctx);
        }
    }

    @Override
    public void setPermissionCacheOptimizer(PermissionCacheOptimizer permissionCacheOptimizer) {
        this.permissionCacheOptimizer = permissionCacheOptimizer;
    }

    private List filterCollection(Collection filterTarget, Expression filterExpression, EvaluationContext ctx) {
        final MethodSecurityExpressionOperations rootObject = (MethodSecurityExpressionOperations) ctx.getRootObject().getValue();
        final boolean debug = logger.isDebugEnabled();
        List retainList = new ArrayList(filterTarget.size());
        if (debug) {
            logger.debug("Filtering with expression: " + filterExpression.getExpressionString());
        }

        if (debug) {
            logger.debug("Filtering collection with " + filterTarget.size() + " elements");
        }

        if (permissionCacheOptimizer != null) {
            permissionCacheOptimizer.cachePermissionsFor(rootObject.getAuthentication(), filterTarget);
        }

        for (Object filterObject : filterTarget) {
            rootObject.setFilterObject(filterObject);

            if (ExpressionUtils.evaluateAsBoolean(filterExpression, ctx)) {
                retainList.add(filterObject);
            }
        }

        if (debug) {
            logger.debug("Retaining elements: " + retainList);
        }
        return retainList;
    }
}
