
module HTTP;
redef signature_files += "hoic.sig";

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

event signature_match(state: signature_state, msg: string, data: string){

       if (/^ddos-hoic/ in state$sig_id){
              local c = state$conn;
  	      Metrics::add_data(HOIC_ATTACK, [$host=c$id$orig_h], 1);
  	      Metrics::add_data(HOIC_VICTIM, [$host=c$id$resp_h], 1);
       }
}