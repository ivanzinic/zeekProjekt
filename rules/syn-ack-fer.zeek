module FERIPLog;

export{
  redef enum Log::ID+={LOG_TARGET_IP};}

@load base/frameworks/logging

type info: record{
        ts: time &log;
        orig_h: addr &log;
        resp_h: addr &log;
        resp_p: port &log;
        msg: string &log;
};

event zeek_init(){
        Log::create_stream(FERIPLog::LOG_TARGET_IP, [$columns=info, $path="rule#1"]);
}

event connection_established(c:connection){

        if (c$id$resp_h == 161.53.72.120){
                local information: info = [$ts=network_time(), $orig_h=c$id$orig_h, $resp_h=c$id$resp_h, $resp_p=c$id$resp_p, $msg="Detektirana konekcija prema FER-u>
                Log::write(FERIPLog::LOG_TARGET_IP, information);}


}



