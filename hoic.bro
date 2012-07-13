
module HTTP;

export {
	redef enum Notice::Type += {
                HOIC_Attack,
		HOIC_Victim,
	};	
	redef enum Metrics::ID += {
		HOIC_ATTACK,
		HOIC_VICTIM
	};
}

event bro_init()
{

## need to work on tuning these.

	Metrics::add_filter(HTTP::HOIC_ATTACK,
	                    [$log=T,
	                     $notice_threshold=5,
	                     $note=HOIC_Attack,
	                     $break_interval=1mins]);
	Metrics::add_filter(HTTP::HOIC_VICTIM,
	                    [$log=T,
	                     $notice_threshold=5,
	                     $note=HOIC_Victim,
	                     $break_interval=1mins]);
}

event tcp_packet(c: connection, is_orig: bool, flags: string, seq: count, ack: 
count, len: count, payload: string){

## We have to look at the TCP payload directly because one of the key
## HOIC signatures is an extra space in the headers which is normally
## obscured by Bro's parsing prior to the http_header event.

    if(is_orig && (c$id$resp_p in HTTP::ports)){
	if(("HTTP/1.0" in payload) && ("Host:" in payload)){
 	    if(":  " in payload){
	    	   print fmt("HOIC ATTACK");
  		    Metrics::add_data(HOIC_ATTACK, [$host=c$id$orig_h], 1);
		    Metrics::add_data(HOIC_VICTIM, [$host=c$id$resp_h], 1);
	    }	    
        }
    }
}