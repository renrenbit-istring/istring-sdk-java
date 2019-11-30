package com.istring.dto.parm;

import lombok.Data;

/**
 * @author d
 * @create 2019-11-28 2:20 PM
 **/
@Data
public class CreateWithdrawParm {
    private String uniqTradeNo;
    private String tokenName;
    private String fromAddress;
    private String toAddress;
    private String memo;
    private String amount;
    private String remark;
}
