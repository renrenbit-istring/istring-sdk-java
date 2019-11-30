package com.istring.dto;

import lombok.Data;

/**
 * @author d
 * @create 2019-11-28 2:29 PM
 **/
@Data
public class IstringParm {
    /**
     * 创建api 时的Istring 系统提供的 公钥
     */
    private String pubKey;
    /**
     * 商户自己的 私钥
     */
    private String prvKey;
    /**
     * https://gateway.istring.com/istring-openapi
     */
    private String baseUrl;
    /**
     * 创建时的 apiKey
     */
    private String apiKey;
}
