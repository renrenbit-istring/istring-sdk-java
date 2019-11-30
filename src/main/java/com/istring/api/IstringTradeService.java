package com.istring.api;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.TypeReference;
import com.istring.IstringDataApi;
import com.istring.dto.IstringResult;
import com.istring.dto.RTradeRecordDTO;
import com.istring.dto.parm.QueryTradeRecordParm;
import com.istring.utils.MyMap;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.util.List;

/**
 * @author d
 * @create 2019-11-03 5:59 PM
 **/
@Slf4j
public class IstringTradeService extends IstringDataApi {

    private static final String  RECORD_LIST = "wallet.query.trade.record";

    public IstringResult<List<RTradeRecordDTO>> records(QueryTradeRecordParm queryParam) {
        MyMap myMap = MyMap.build()
                .addPut("tradeType", queryParam.getTradeType())
                .addPut("page", queryParam.getPage())
                .addPut("businessType", queryParam.getBusinessType())
                .addPut("size", queryParam.getSize());
        try {
            String data = postData(RECORD_LIST, myMap);
            IstringResult<List<RTradeRecordDTO>> listIstringResult = JSON.parseObject(data, new TypeReference<IstringResult<List<RTradeRecordDTO>>>() {
            });
            return listIstringResult;
        } catch (IOException e) {
            log.error("获取ISTRING用户地址列表失败:{}", queryParam , e);
            e.printStackTrace();
        }
        return null;

    }
}
