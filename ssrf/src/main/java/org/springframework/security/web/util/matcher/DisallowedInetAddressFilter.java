package org.springframework.security.web.util.matcher;

import java.net.InetAddress;
import java.util.List;

final class DisallowedInetAddressFilter implements InetAddressFilter {

	private final List<IpAddressMatcher> disallowList;

	public DisallowedInetAddressFilter(List<String> disallowList) {
		this.disallowList = disallowList.stream().map(IpAddressMatcher::new).toList();
	}

	@Override
	public boolean filter(InetAddress address) {
		for (IpAddressMatcher matcher : this.disallowList) {
			if (matcher.matches(address)) {
				return false;
			}
		}
		return true;
	}

	@Override
	public String toString() {
		return "DisallowedInetAddressFilter[\"" + this.disallowList + "\"]";
	}

}
