package com.istring;

import com.istring.api.IstringAccountService;
import com.istring.dto.AccountDTO;
import com.istring.dto.IstringParm;
import com.istring.dto.IstringResult;

import java.util.List;

/**
 * @author d
 * @create 2019-11-28 1:16 PM
 **/
public class Test {
    public static void main(String[] a) {
        IstringParm istringParm = new IstringParm();
        //设置自己的ISTRING信息
        IstringAccountService accountService = new IstringAccountService();
        accountService.setIstringParm(istringParm);
        IstringResult<List<AccountDTO>> amount = accountService.amount();
        System.out.println(amount);
    }
}
