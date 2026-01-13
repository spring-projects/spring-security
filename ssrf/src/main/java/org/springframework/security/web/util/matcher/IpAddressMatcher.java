package org.springframework.security.web.util.matcher;

import java.net.InetAddress;
import java.net.UnknownHostException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

// Inspired by and to be merged back into
// org.springframework.security.web.util.matcher.IpAddressMatcher.java

class IpAddressMatcher {

	private static final Log logger = LogFactory.getLog(IpAddressMatcher.class);

	private final InetAddress address;

	private final int nMaskBits;


	public IpAddressMatcher(String addressOrRange) {
		if (addressOrRange.indexOf('/') > 0) {
			String[] addressAndMask = addressOrRange.split("/");
			address = parse(addressAndMask[0]);
			this.nMaskBits = Integer.parseInt(addressAndMask[1]);
		} else {
			this.nMaskBits = -1;
			address = parse(addressOrRange);
		}
	}

	private static InetAddress parse(String address) {
		try {
			InetAddress result = InetAddress.getByName(address);
			if (address.matches(".*[a-zA-Z\\-].*$") && !address.contains(":")) {
				logger.warn("Hostname '" + address + "' resolved to " + result.toString()
						+ " will be used on IP address matching");
			}
			return result;
		} catch (UnknownHostException ex) {
			throw new IllegalArgumentException(String.format("Failed to parse address '%s'", address), ex);
		}
	}


	public boolean matches(InetAddress toCheck) {
		if (this.nMaskBits < 0) {
			return toCheck.equals(this.address);
		}
		byte[] remAddr = toCheck.getAddress();
		byte[] reqAddr = this.address.getAddress();
		int nMaskFullBytes = this.nMaskBits / 8;
		byte finalByte = (byte) (0xFF00 >> (this.nMaskBits & 0x07));
		for (int i = 0; i < nMaskFullBytes; i++) {
			if (remAddr[i] != reqAddr[i]) {
				return false;
			}
		}
		if (finalByte != 0) {
			return (remAddr[nMaskFullBytes] & finalByte) == (reqAddr[nMaskFullBytes] & finalByte);
		}
		return true;
	}

	@Override
	public String toString() {
		return "IpAddressMatcher{address=" + this.address + ", nMaskBits=" + this.nMaskBits + '}';
	}

}
