package com.istring.api;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.TypeReference;
import com.istring.IstringDataApi;
import com.istring.dto.IstringResult;
import com.istring.dto.parm.CreateWithdrawParm;
import com.istring.utils.MyMap;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;

/**
 * @author d
 * @create 2019-11-03 5:12 PM
 **/
@Slf4j
public class IstringWithdrawService extends IstringDataApi {

    private static final String SEND_COIN = "wallet.transfer";

    public IstringResult<String> send(CreateWithdrawParm withdrawParam) {
        MyMap myMap = MyMap.build()
                .addPut("amount", withdrawParam.getAmount())
                .addPut("toAddress", withdrawParam.getToAddress())
                .addPut("coinName", withdrawParam.getTokenName())
                .addPut("memo", withdrawParam.getMemo())
                .addPut("uniqueTransactionNo", withdrawParam.getUniqTradeNo())
                .addPut("remark",withdrawParam.getRemark())
                .addPut("fromAddress",withdrawParam.getFromAddress());
        try {
            String data = postData(SEND_COIN, myMap);
            IstringResult<String> listIstringResult = JSON.parseObject(data, new TypeReference<IstringResult<String>>() {
            });
            return listIstringResult;
        } catch (IOException e) {
            log.error("获取ISTRING用户地址列表失败:{}", withdrawParam , e);
            e.printStackTrace();
        }
        return null;
    }
}
