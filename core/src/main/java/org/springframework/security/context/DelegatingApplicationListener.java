/*
 * Copyright 2002-2016 the original author or authors.
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
package org.springframework.security.context;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationListener;
import org.springframework.context.event.SmartApplicationListener;
import org.springframework.util.Assert;

/**
 * Used for delegating to a number of SmartApplicationListener instances. This is useful
 * when needing to register an SmartApplicationListener with the ApplicationContext
 * programmatically.
 *
 * @author Rob Winch
 */
public final class DelegatingApplicationListener implements ApplicationListener<ApplicationEvent> {

	private List<SmartApplicationListener> listeners = new CopyOnWriteArrayList<>();

	@Override
	public void onApplicationEvent(ApplicationEvent event) {
		if (event == null) {
			return;
		}
		for (SmartApplicationListener listener : this.listeners) {
			Object source = event.getSource();
			if (source != null && listener.supportsEventType(event.getClass())
					&& listener.supportsSourceType(source.getClass())) {
				listener.onApplicationEvent(event);
			}
		}
	}

	/**
	 * Adds a new SmartApplicationListener to use.
	 * @param smartApplicationListener the SmartApplicationListener to use. Cannot be
	 * null.
	 */
	public void addListener(SmartApplicationListener smartApplicationListener) {
		Assert.notNull(smartApplicationListener, "smartApplicationListener cannot be null");
		this.listeners.add(smartApplicationListener);
	}

}
