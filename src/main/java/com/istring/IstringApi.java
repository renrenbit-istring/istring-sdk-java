package com.istring;

import com.alibaba.fastjson.JSON;
import com.istring.utils.EncryptUtil;
import com.istring.utils.OKHttpUtils;
import com.istring.utils.SignHashMap;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * @author d
 * @create 2019-10-29 1:41 PM
 **/
@Slf4j
public class IstringApi {

    private String baseUrl;
    private String apiKey;
    private String pubKey;
    private String privateKey;

    public static IstringApi getClient(String baseUrl,String apiKey,String pubKey,String privateKey) {
        return new IstringApi(baseUrl,apiKey,pubKey,privateKey);
    }

    private IstringApi(String baseUrl, String apiKey, String pubKey, String privateKey) {
        this.baseUrl = baseUrl;
        this.apiKey = apiKey;
        this.pubKey = pubKey;
        this.privateKey = privateKey;
    }
    public String api(String apiUrl,String apiPath,Object apiPram) throws IOException {
        SignHashMap commonParam = new SignHashMap();
        commonParam.put("apiKey", apiKey);
        commonParam.put("method", apiPath);
        commonParam.put("timestamp", System.currentTimeMillis());
        commonParam.put("version", "1.0");
        String jsonParam = JSON.toJSONString(apiPram);
        String aesSalt = EncryptUtil.generateAESKey();
        String aesEncryptResult = EncryptUtil.aesEncryptByECBPKCS7Padding(jsonParam, aesSalt);
        commonParam.put("bizContent", aesEncryptResult);
        String rsaEncryptResult = EncryptUtil.rsaEncrypt(aesSalt, pubKey, "UTF-8");
        commonParam.put("salt", rsaEncryptResult);

        String signContent = EncryptUtil.sortClearingSignContent(commonParam);
        String sha256SignContent = EncryptUtil.sha256Base64(signContent);
        String rsaSign = EncryptUtil.rsaSign(sha256SignContent,privateKey, "UTF-8");
        commonParam.put("sign", rsaSign);
        String paramJson = JSON.toJSONString(commonParam);
        log.info("istring parm:{}",paramJson);
        Map<String,String> header = new HashMap<>();
        //注意后台的IP白名单，失败有可能是白名单引起的
        String data = OKHttpUtils.postJson(baseUrl + apiUrl, paramJson , header);
        return data;
    }
}