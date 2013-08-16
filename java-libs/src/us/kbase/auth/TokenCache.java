package us.kbase.auth;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Caches tokens to avoid network queries to the token provider.
 * 
 * Tokens are stored until the size of the cache is greater than the maximum
 * allowed size. Tokens are then ordered by most recent access and the oldest
 * tokens are discared to return the cache to its nominal size.
 * 
 * This class is thread safe.
 * 
 * @author gaprice@lbl.gov
 *
 */
public class TokenCache {
	
	/**
	 * Default nominal size of the cache.
	 */
	final public static int DEFAULT_SIZE = 1000;
	/**
	 * Default maximum size of the cache.
	 */
	final public static int DEFAULT_MAX_SIZE = 2000;
	
	final private int size;
	final private int maxsize;
	final private ConcurrentHashMap<String, Date> cache = new ConcurrentHashMap<String, Date>();
	
	/**
	 * Create a new TokenCache.
	 * @param size the nominal size of the cache in tokens
	 * @param maxsize the maximum size of the cache in tokens
	 */
	public TokenCache(int size, int maxsize) {
		if (size < 1 || maxsize < 1) {
			throw new IllegalArgumentException("size and maxsize must be > 0");
		}
		if (size >= maxsize) {
			throw new IllegalArgumentException("size must be < maxsize");
		}
		this.size = size;
		this.maxsize = maxsize;
	}
	
	/**
	 * Create a new TokenCache with the default max size.
	 * @param size the nominal size of the cache in tokens
	 */
	public TokenCache(int size) {
		this(size, DEFAULT_MAX_SIZE);
	}
	
	/**
	 * Create a new TokenCache with default parameters.
	 */
	public TokenCache() {
		this(DEFAULT_SIZE);
	}
	
	/**
	 * Determine whether a token is in the cache.
	 * @param token the token to check
	 * @return <code>true</code> if the token is in the cache, <code>false</code>
	 * otherwise.
	 * @throws TokenExpiredException if the token is expired.
	 */
	public boolean hasToken(AuthToken token) throws TokenExpiredException {
		return checkToken(token).tokenInCache;
	}
	
	private MD5Bool checkToken(AuthToken token) throws TokenExpiredException {
		if(token.isExpired()) {
			throw new TokenExpiredException("token expired");
		}
		String tokmd = tokenToMD5(token);
		if(cache.containsKey(tokmd)) {
			cache.put(tokmd, new Date());
			return new MD5Bool(true, tokmd);
		}
		return new MD5Bool(false, tokmd);
	}
	
	/**
	 * Add a token to the cache. This method assumes the token is valid.
	 * @param token the token to add
	 * @throws TokenExpiredException if the token is expired.
	 */
	public void putValidToken(AuthToken token) throws TokenExpiredException {
		final MD5Bool sb = checkToken(token);
		if(sb.tokenInCache) {return;}
		cache.put(sb.tokenMD5, new Date());
		synchronized (cache) { // block here otherwise all threads may start sorting
			if(cache.size() <= maxsize) {return;}
			List<DateMD5> dmd5s = new ArrayList<DateMD5>();
			for (String s: cache.keySet()) {
				dmd5s.add(new DateMD5(cache.get(s), s));
			}
			Collections.sort(dmd5s);
			for(int i = size; i < dmd5s.size(); i++) {
				cache.remove(dmd5s.get(i).md5);
			}
		}
	}
	
	private static String tokenToMD5(AuthToken token) {
		MessageDigest md = null;
		try {
			md = MessageDigest.getInstance("md5");
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException("No md5", e);
		}
		return bytesToHex(md.digest(token.toString().getBytes()));
	}

	// from http://stackoverflow.com/questions/9655181/convert-from-byte-array-to-hex-string-in-java
	final private static char[] hexArray = {'0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'};
	private static String bytesToHex(byte[] bytes) {
		char[] hexChars = new char[bytes.length * 2];
		int v;
		for ( int j = 0; j < bytes.length; j++ ) {
			v = bytes[j] & 0xFF;
			hexChars[j * 2] = hexArray[v >>> 4];
			hexChars[j * 2 + 1] = hexArray[v & 0x0F];
		}
		return new String(hexChars);
	}
}

class MD5Bool {
	
	boolean tokenInCache;
	String tokenMD5;

	MD5Bool(boolean tokenInCache, String md5) {
		this.tokenInCache = tokenInCache;
		this.tokenMD5 = md5;
	}
	
}

class DateMD5 implements Comparable<DateMD5>{

	final String md5;
	final Date date;
	
	DateMD5(Date date, String md5) {
		this.md5 = md5;
		this.date = date;
	}
	
	@Override
	public int compareTo(DateMD5 dmd5) {
		return -this.date.compareTo(dmd5.date); //descending
	}
	
}