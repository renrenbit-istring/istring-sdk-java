package com.istring.dto.parm;

import lombok.Data;

/**
 * @author d
 * @create 2019-11-28 2:17 PM
 **/
@Data
public class QueryTradeRecordParm {
    private Integer tradeType;
    private Integer businessType;
    private int page;
    private int size;
}
