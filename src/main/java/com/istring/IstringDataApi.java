package com.istring;

import com.istring.dto.IstringParm;
import lombok.extern.slf4j.Slf4j;
import java.io.IOException;

/**
 * @author d
 * @create 2019-11-03 2:24 PM
 **/
@Slf4j
public class IstringDataApi {

    private static final String OK = "20000";
    private static final String ERROR = "40002";

    private IstringParm istringParm;

    public void setIstringParm(IstringParm istringParm) {
        this.istringParm = istringParm;
    }

    private IstringApi istringApi;

    private static final String apiUrl = "/p/api/gateway.do";

    public IstringApi getIstringApi() {
        if (this.istringApi == null) {
            istringApi = IstringApi.getClient(istringParm.getBaseUrl(),istringParm.getApiKey(),istringParm.getPubKey(),istringParm.getPrvKey());
        }
        return istringApi;
    }

    public String postData(String apiPath ,Object parm) throws IOException {
        log.info("调用 Isring API,{},{}",apiPath,parm);
        String apiData = getIstringApi().api(apiUrl, apiPath, parm);
        log.info("调用 Isring API 返回值,{},{},{}",apiPath,parm,apiData);
        return apiData;
    }


}
