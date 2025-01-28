@load base/protocols/http
@load base/frameworks/logging

module HTTP;

export {
    redef enum Log::ID += { Failed_HTTPS_Login };
}

type info: record{
        ts: time &log;
        orig_h: addr &log;
        resp_h: addr &log;
        status_code: count  &log;
};

event zeek_init(){
        Log::create_stream(HTTP::Failed_HTTPS_Login, [$columns=info, $path="rule#2"]);
}

event http_reply(c:connection, version: string, code: count, reason: string) {
        if (code==401){
            local information: info=[$ts=network_time(), $orig_h=c$id$orig_h, $resp_h=c$id$resp_h,  $status_code=code];
            Log::write(HTTP::Failed_HTTPS_Login, information);
        }
}




