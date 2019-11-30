package com.istring.utils;

import java.util.Collection;
import java.util.Collections;
import java.util.Map;

/**
 * @author d
 * @create 2019-11-28 1:20 PM
 **/
public class CollectionUtils {
    public static boolean isEmpty(Collection collection) {
        return collection == null || collection.isEmpty();
    }
    public static boolean isEmpty(Map collection) {
        return collection == null || collection.isEmpty();
    }
}
