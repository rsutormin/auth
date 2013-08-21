package us.kbase.auth;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Caches strings with an expiry time.
 * 
 * Strings are stored until the size of the cache is greater than the maximum
 * allowed size. Strings are then ordered by most recent access and the oldest
 * strings are discarded to return the cache to its nominal size.
 * 
 * This class is thread safe.
 * 
 * @author gaprice@lbl.gov
 *
 */
public class StringCache {
	// is there some way to share code with tokencache? Doesn't seem so...
	
	/**
	 * Default nominal size of the cache.
	 */
	final public static int DEFAULT_SIZE = 1000;
	/**
	 * Default maximum size of the cache.
	 */
	final public static int DEFAULT_MAX_SIZE = 2000;
	/**
	 * Default expiry time for strings.
	 */
	final public static long EXPIRY = 24 * 60 * 60;
	
	final private int size;
	final private int maxsize;
	private long expiry = EXPIRY;
	final private ConcurrentHashMap<String, Date> cache;
	
	/**
	 * Create a new StringCache.
	 * @param size the nominal size of the cache in strings
	 * @param maxsize the maximum size of the cache in strings
	 */
	public StringCache(int size, int maxsize) {
		if (size < 1 || maxsize < 1) {
			throw new IllegalArgumentException("size and maxsize must be > 0");
		}
		if (size >= maxsize) {
			throw new IllegalArgumentException("size must be < maxsize");
		}
		this.size = size;
		this.maxsize = maxsize;
		cache = new ConcurrentHashMap<String, Date>(maxsize);
	}
	
	/**
	 * Create a new StringCache with the default max size.
	 * @param size the nominal size of the cache in strings
	 */
	public StringCache(int size) {
		this(size, DEFAULT_MAX_SIZE);
	}
	
	/**
	 * Create a new StringCache with default parameters.
	 */
	public StringCache() {
		this(DEFAULT_SIZE);
	}
	
	/**
	 * Set the lifetime of a string in the cache.
	 * @param seconds the lifetime of a string
	 */
	public void setExpiry(long seconds) {
		if (seconds < 1) {
			throw new IllegalArgumentException("seconds must be > 0");
		}
		expiry = seconds;
	}
	
	/**
	 * Get the lifetime of a string in the cache.
	 */
	public long getExpiry() {
		return expiry;
	}
	
	/**
	 * Determine whether a string is in the cache.
	 * @param token the string to check
	 * @return <code>true</code> if the string is in the cache, <code>false</code>
	 * otherwise.
	 */
	public boolean hasString(String string) {
		if (!cache.containsKey(string)) {
			return false;
		}
		if (new Date().getTime() - cache.get(string).getTime() > expiry * 1000) {
			return false;
		}
		cache.put(string, new Date());
		return true;
	}
		
	/**
	 * Add a string to the cache.
	 * @param string the string to add
	 */
	public void putString(String string) {
		cache.put(string, new Date());
		synchronized (cache) { // block here otherwise all threads may start sorting
			if(cache.size() <= maxsize) {return;}
			List<DateString> ds = new ArrayList<DateString>();
			for (String s: cache.keySet()) {
				ds.add(new DateString(cache.get(s), s));
			}
			Collections.sort(ds);
			for(int i = size; i < ds.size(); i++) {
				cache.remove(ds.get(i).string);
			}
		}
	}
}

class DateString implements Comparable<DateString>{

	final String string;
	final Date date;
	
	DateString(Date date, String string) {
		this.string = string;
		this.date = date;
	}
	
	@Override
	public int compareTo(DateString ds) {
		return -this.date.compareTo(ds.date); //descending
	}
	
}