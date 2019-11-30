package com.istring.api;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.TypeReference;
import com.istring.IstringDataApi;
import com.istring.dto.IstringResult;
import com.istring.dto.parm.CreateAddressParm;
import com.istring.utils.MyMap;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.util.List;

/**
 * @author d
 * @create 2019-11-03 2:23 PM
 **/
@Slf4j
public class IstringAddressService extends IstringDataApi {

    private static final String CREATE = "wallet.create.address";

    public IstringResult<List<String>> create(CreateAddressParm addressParam) {
        MyMap myMap = MyMap.build()
                .addPut("count", addressParam.getCount())
                .addPut("coinName", addressParam.getTokenName());
        try {
            String data = postData(CREATE, myMap);
            IstringResult<List<String>> listIstringResult = JSON.parseObject(data, new TypeReference<IstringResult<List<String>>>() {
            });
            return listIstringResult;

        } catch (IOException e) {
            log.error("获取ISTRING用户地址列表失败:{}", addressParam , e);
            e.printStackTrace();
        }
        return null;
    }
}