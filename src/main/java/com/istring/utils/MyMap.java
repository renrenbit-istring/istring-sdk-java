package com.istring.utils;

import java.util.HashMap;

/**
 * @author d
 * @create 2019-06-28 5:23 PM
 **/
public class MyMap<K,V> extends HashMap<K,V> {
    public static <K,V> MyMap build() {
        MyMap<K,V> map = new MyMap<>();
        return map;
    }
    public MyMap<K,V> addPut(K k,V v) {
        this.put(k,v);
        return this;
    }
}
