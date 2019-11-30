package com.istring.dto;

import lombok.Data;

@Data
public class AccountDTO {
    /**
     * 商户户余额
     */
    private String availableAmount;
    /**
     * 商户冻结余额
     */
    private String freezeAmount;
    /**
     * 币名称
     */
    private String coinName;
}
