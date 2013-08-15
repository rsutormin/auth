package us.kbase.auth;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;

class TokenCache {
	
	final static int DEFAULT_SIZE = 1000;
	final static int DEFAULT_MAX_SIZE = 1000;
	
	final private int size;
	final private int maxsize;
	final private long expires;
	final private HashMap<String, Date> cache = new HashMap<>();
	
	TokenCache(int size, int maxsize, long expiresSeconds) {
		this.size = size;
		this.maxsize = maxsize;
		this.expires = expiresSeconds;
	}
	
	TokenCache(int size, int maxsize) {
		this(size, maxsize, AuthToken.DEFAULT_EXPIRES);
	}
	
	TokenCache(int size, long expiresSeconds) {
		this(size, DEFAULT_MAX_SIZE, expiresSeconds);
	}
	
	TokenCache(long expiresSeconds) {
		this(DEFAULT_SIZE, expiresSeconds);
	}
	
	TokenCache(int size) {
		this(size, DEFAULT_MAX_SIZE);
	}
	
	TokenCache() {
		this(DEFAULT_SIZE);
	}
	
	boolean hasToken(AuthToken token) throws TokenExpiredException {
		return checkToken(token).tokenInCache;
	}
	
	private MD5Bool checkToken(AuthToken token) throws TokenExpiredException {
		if(token.isExpired(expires)) {
			throw new TokenExpiredException("token expired");
		}
		String tokmd = tokenToMD5(token);
		if(cache.containsKey(tokmd)) {
			cache.put(tokmd, new Date());
			return new MD5Bool(true, tokmd);
		}
		return new MD5Bool(false, tokmd);
	}
	
	void putValidToken(AuthToken token) throws TokenExpiredException {
//		if(token.isExpired(expires)) {
//			throw new TokenExpiredException("token expired");
//		}
//		String tokmd = tokenToMD5(token);
//		if(cache.containsKey(tokmd)) {
//			cache.put(tokmd, new Date());
//			return;
//		}
		final MD5Bool sb = checkToken(token);
		if(sb.tokenInCache) {return;}
		cache.put(sb.tokenMD5, new Date());
		if(cache.size() <= maxsize) {
			return;
		}
		List<DateMD5> dmd5s = new ArrayList<>();
		for (String s: cache.keySet()) {
			dmd5s.add(new DateMD5(cache.get(s), s));
		}
		Collections.sort(dmd5s);
		for(int i = size; i < dmd5s.size(); i++) {
			cache.remove(dmd5s.get(i).md5);
		}
	}
	
	private String tokenToMD5(AuthToken token) {
		MessageDigest md = null;
		try {
			md = MessageDigest.getInstance("md5");
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException("No md5", e);
		}
		return new String(md.digest(token.toString().getBytes()));
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