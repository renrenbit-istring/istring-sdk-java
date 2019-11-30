package com.istring.api;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.TypeReference;
import com.istring.IstringDataApi;
import com.istring.dto.AccountDTO;
import com.istring.dto.IstringResult;
import com.istring.utils.CollectionUtils;
import com.istring.utils.MyMap;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.util.List;
import java.util.Optional;

/**
 * @author d
 * @create 2019-11-14 12:25 AM
 **/
@Slf4j
public class IstringAccountService extends IstringDataApi {

    static final String BALANCE = "wallet.query.balance";

    public IstringResult<List<AccountDTO>> amount() {
        MyMap myMap = MyMap.build();
        try {
            String data = postData(BALANCE, myMap);
            IstringResult<List<AccountDTO>> listIstringResult = JSON.parseObject(data, new TypeReference<IstringResult<List<AccountDTO>>>() {
            });
            return listIstringResult;
        } catch (IOException e) {
            log.error("获取ISTRING用户余额列表失败:{}" , e);
            e.printStackTrace();
        }
        return null;
    }

    public AccountDTO getAccountByName(String name) {
        IstringResult<List<AccountDTO>> amount = this.amount();
        if (amount!= null) {
            if (!CollectionUtils.isEmpty(amount.getData())) {
                Optional<AccountDTO> first = amount.getData().stream().filter(x -> x.getCoinName().equals(name)).findFirst();
                if(first.isPresent()) {
                    return first.get();
                }
            }
        }
        return null;
    }
}
