package com.istring.dto;

import lombok.Data;

/**
 * @author d
 * @create 2019-11-03 4:11 PM
 **/
@Data
public class IstringResult<T extends Object> {
    private String code;
    private String errMsg;
    private T data;
}
