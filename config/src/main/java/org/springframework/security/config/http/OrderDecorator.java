/*
 * Copyright 2020 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.config.http;

import org.springframework.beans.BeanMetadataElement;
import org.springframework.core.Ordered;

/**
 * Wrapper to provide ordering to a {@link BeanMetadataElement}.
 *
 * @author Rob Winch
 */
class OrderDecorator implements Ordered {

	final BeanMetadataElement bean;

	final int order;

	OrderDecorator(BeanMetadataElement bean, SecurityFilters filterOrder) {
		this.bean = bean;
		this.order = filterOrder.getOrder();
	}

	OrderDecorator(BeanMetadataElement bean, int order) {
		this.bean = bean;
		this.order = order;
	}

	@Override
	public int getOrder() {
		return this.order;
	}

	@Override
	public String toString() {
		return this.bean + ", order = " + this.order;
	}

}
