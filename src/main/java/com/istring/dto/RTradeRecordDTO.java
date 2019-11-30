package com.istring.dto;

import lombok.Data;

/**
 * @author d
 * @create 2019-11-28 2:18 PM
 **/
@Data
public class RTradeRecordDTO {
    private String uniqTradeNo;
    private String tradeNo;
    private String tokenName;
    private Integer tradeType;
    private Integer businessType;
    private String tradeAmount;
    private String tradeFee;
    private String tradeFeeTokenName;
    private String fromAddress;
    private String toAddress;
    private String txHash;
    private Integer txStatus;
    private Integer outIndex;
    private Long blockTimestamp;
    private Long blockHeight;
}
