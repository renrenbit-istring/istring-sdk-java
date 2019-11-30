package com.istring.utils;

import com.alibaba.fastjson.JSON;
import org.apache.commons.lang3.StringUtils;

import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.TimeZone;

public class SignHashMap extends HashMap<String, String> {

	private static final long serialVersionUID = -5040463526048486631L;

	public SignHashMap() {
		super();
	}

	public SignHashMap(Map<? extends String, ? extends String> m) {
		super(m);
	}

	public String put(String key, Object value) {
		String strValue;

		if (value == null) {
			strValue = null;
		} else if (value instanceof String) {
			strValue = (String) value;
		} else if (value instanceof Integer) {
			strValue = ((Integer) value).toString();
		} else if (value instanceof Long) {
			strValue = ((Long) value).toString();
		} else if (value instanceof Float) {
			strValue = ((Float) value).toString();
		} else if (value instanceof Double) {
			strValue = ((Double) value).toString();
		} else if (value instanceof Boolean) {
			strValue = ((Boolean) value).toString();
		} else if (value instanceof Date) {
			DateFormat format = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
			format.setTimeZone(TimeZone.getTimeZone("GMT+8"));
			strValue = format.format((Date) value);
		} else {
			strValue = JSON.toJSONString(value);
		}

		return this.put(key, strValue);
	}

	public String put(String key, String value) {
		if (StringUtils.isNoneBlank(key, value)) {
			return super.put(key, value);
		} else {
			return null;
		}
	}
}
