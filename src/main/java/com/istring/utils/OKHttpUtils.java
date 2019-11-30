package com.istring.utils;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.TypeReference;
import lombok.extern.slf4j.Slf4j;
import okhttp3.FormBody;
import okhttp3.Headers;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import org.apache.commons.lang3.StringUtils;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * @author
 * @create 2018-06-16 上午11:48
 **/
@Slf4j
public class OKHttpUtils {
    final static OkHttpClient CLIENT = new OkHttpClient.Builder()
            .connectTimeout(20, TimeUnit.SECONDS)
            .writeTimeout(20,TimeUnit.SECONDS)
            .readTimeout(20, TimeUnit.SECONDS)
            .build();
    static {
        CLIENT.dispatcher().setMaxRequests(500);
        CLIENT.dispatcher().setMaxRequestsPerHost(10);
    }
    /**
     * 发起get请求
     *
     * @param url
     * @return
     */
    public static String httpGet(String url) {
        log.debug("获取网络数据:{}",url);
        String result = "";
        Request request = new Request.Builder().url(url).build();
        try {
            Response response = CLIENT.newCall(request).execute();
            result = response.body().string();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return result;
    }

    public static String httpGet(String url , Map<String,Object> map) {
        return httpGet(url,map,null);
    }

    /**
     * 发起get请求
     *
     * @param url
     * @return
     */
    public static String httpGet(String url , Map<String,Object> map , Map<String,String> headers) {
        String result = "";

        String urlParamsByMap = getUrlParamsByMap(map);

        if (!StringUtils.isBlank(urlParamsByMap)) {
            url += "?" + urlParamsByMap;
        }
        log.debug("获取网络数据:{}",url);
        Request request = new Request.Builder().url(url)
                .headers(CollectionUtils.isEmpty(headers) ? new Headers.Builder().build() : Headers.of(headers))
                .build();
        try {
            Response response = CLIENT.newCall(request).execute();
            result = response.body().string();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return result;
    }

    /**
     * 将map转换成url
     *
     * @param map
     * @return
     */
    public static String getUrlParamsByMap(Map<String, Object> map) {
        if (CollectionUtils.isEmpty(map)) {
            return "";
        }
        StringBuffer sb = new StringBuffer();
        for (Map.Entry<String, Object> entry : map.entrySet()) {
            sb.append(entry.getKey() + "=" + URLEncoder.encode(entry.getValue().toString()) );
            sb.append("&");
        }
        String s = sb.toString();
        if (s.endsWith("&")) {
            s = StringUtils.substringBeforeLast(s, "&");
        }
        return s;
    }

    public static String getUrl(String url,Object... objects) {
        if(objects.length>0)
        {
            for (int i = 0; i < objects.length; i++) {
                try {
                    objects[i] = URLEncoder.encode(objects[i].toString(),"utf-8");
                } catch (UnsupportedEncodingException e) {
                    e.printStackTrace();
                }
            }

            url = String.format(url,objects);
        }
        return url;
    }

//    public static String httpGet(String url,Object... objects) {
//        String url1 = getUrl(url, objects);
//        return httpGet(url1);
//    }

    /**
     * 发送httppost请求
     *
     * @param url
     * @param data  提交的参数为key=value&key1=value1的形式
     * @return
     */
    public static String httpPost(String url, Map<String,String> data) {
        return httpPost(url, data, null);
    }


    /**
     * 发送httppost请求
     *
     * @param url
     * @param data  提交的参数为key=value&key1=value1的形式
     * @return
     */
    public static String httpPost(String url, Map<String,String> data ,Map<String,String> headers) {
        String result = null;
        FormBody.Builder builder = new FormBody.Builder();
        data.forEach((k,v) -> builder.add(k,v));

        RequestBody requestBody = builder.build();
        Request request = new Request.Builder()
                .url(url)
                .post(requestBody)
                .headers(CollectionUtils.isEmpty(headers) ? new Headers.Builder().build() : Headers.of(headers))
                .build();
        try {
            Response response = CLIENT.newCall(request).execute();
            result = response.body().string();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return result;
    }


    public static final MediaType AJAX_JSON = MediaType.parse("application/json; charset=utf-8");

    public static String postJson(String url, String json , Map<String,String> headers) throws IOException {
        RequestBody body = RequestBody.create(AJAX_JSON, json);
        Request request = new Request.Builder()
                .url(url)
                .post(body)
                .headers(CollectionUtils.isEmpty(headers) ? new Headers.Builder().build() : Headers.of(headers))
                .build();
        Response response = CLIENT.newCall(request).execute();
        if (response.isSuccessful()) {
            return response.body().string();
        } else {
            throw new IOException("Unexpected code " + response);
        }
    }
    public <T extends Object> T get(String url,TypeReference<T> object)
    {
        String httpGet = OKHttpUtils.httpGet(url);
        if (StringUtils.isEmpty(httpGet)) {
            return null;
        }
        T t = JSON.parseObject(httpGet, object);
        return t;
    }

    public static String postJson(String url, String json) throws IOException {
        return postJson(url, json, null);
    }

}