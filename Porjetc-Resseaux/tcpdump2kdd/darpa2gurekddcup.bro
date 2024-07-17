global num_conn=0;

type konexioa: record {
  num_conn : count &default = 0;
  
  orig_h : string;
  resp_h : string;
  orig_p : string;
  resp_p : string;

  duration : string &default = "0";
  protokoloa : string &default = "tcp";
  service : string &default = "";
  flag : string &default = "OTH";
  src_bytes : string &default = "0";
  dst_bytes : string &default = "0";
  land : count &default = 0;
  wrong_fragment : count &default = 0;
  urg: count &default = 0;
  hot : count &default = 0;
  num_failed_logins: count &default = 0;
  logged_in : count &default = 0;
  num_compromised : count &default = 0;
  root_shell : count &default = 0;
  root_shell_num : count &default = 0;
  su_attempted : count &default = 0;
  num_root : count &default = 0;
  num_file_creations : count &default = 0;
  num_shells : count &default = 0;
  rootDa : bool &default = F;
  num_access_files : count &default = 0;
  num_outbound_cmds : count &default = 0;
  is_hot_login : count &default = 0;
  is_guest_login : count &default = 0;
  
  f1 : file;
  f2 : file;
  f3 : file;
  fitxSortuak : bool &default = F;
  
  payDu : bool &default = F;
  payload : string &default = "";

  isOrig : bool &default = T;
};

global konexioak: table[string, string, addr, port, addr, port] of konexioa;
global konexioaktcp: table[string, addr, port, addr, port] of konexioa;

type byte: record {
  src_bytes : count &default = 0;
  dst_bytes : count &default = 0;
};
global byteak: table[string, addr, port, addr, port] of byte;

const conn_closed = { TCP_CLOSED, TCP_RESET };

function conn_state(c: connection, trans: string): string
  {
  #Konexioaren egoera lortu
  
  local os = c$orig$state;
  local rs = c$resp$state;

  local o_inactive = os == TCP_INACTIVE || os == TCP_PARTIAL;
  local r_inactive = rs == TCP_INACTIVE || rs == TCP_PARTIAL;

  if ( trans == "tcp" ){
    if ( rs == TCP_RESET ){
      if ( os == TCP_SYN_SENT || os == TCP_SYN_ACK_SENT || (os == TCP_RESET && c$orig$size == 0 && c$resp$size == 0) )
        return "REJ";
      else if ( o_inactive )
        return "RSTRH";
      else
        return "RSTR";
    }
    else if ( os == TCP_RESET )
      return r_inactive ? "RSTOS0" : "RSTO";
    else if ( rs == TCP_CLOSED && os == TCP_CLOSED )
      return "SF";
    else if ( os == TCP_CLOSED )
      return r_inactive ? "SH" : "S2";
    else if ( rs == TCP_CLOSED )
      return o_inactive ? "SHR" : "S3";
    else if ( os == TCP_SYN_SENT && rs == TCP_INACTIVE )
      return "S0";
    else if ( os == TCP_ESTABLISHED && rs == TCP_ESTABLISHED )
      return "S1";
    else
      return "OTH";
  }
  else if ( trans == "udp" ){
    if ( os == UDP_ACTIVE )
      return rs == UDP_ACTIVE ? "SF" : "S0";
    else
      return rs == UDP_ACTIVE ? "SHR" : "OTH";
  }

  else if ( trans == "icmp" )
    if ( c$orig$size > 0 ){
      if ( c$resp$size > 0 )
          return "SF";
      else
          return "SH";
    }  
    else if ( c$resp$size > 0 )
      return "SHR";           
    else
      return "OTH";
  else
    return "OTH";
  }

# TCP eta UDPrako
function service_name(p: port): string
{
  # Erantzuten duen konexioaren zerbitzu izena itzultzen du (http,ftp,...)
  if ((49152/tcp<=p && p<=65535/tcp) || (49152/udp<=p && p<=65535/udp))
    return "private";
  else if ((p==4231/tcp) || (p==4231/udp) || (p==43/tcp) || (p==43/udp))
    return "whois";
  else if ((p==194/tcp) || (p==194/udp) ||  
      (p==529/tcp) || (p==529/udp) || 
      (p==2218/tcp) || (p==2218/udp) ||
      (p==6665/tcp) || (p==529/udp) || 
      (p==6666/tcp) || (p==6666/udp) || 
      (p==6667/tcp) || (p==6667/udp) ||
      (p==6668/tcp) || (p==6668/udp) ||
      (p==6669/tcp) || (p==6669/udp) )
    return "IRC";
  else if ((p==531/tcp) || (5190/tcp<=p && p<=5193/tcp))
    return "aol";
  else if ((p==113/tcp) || (p==31/tcp) || (p==56/tcp) || (p==222/tcp) ||  (p==353/tcp) || (p==370/tcp) ||
      (p==1615/tcp) || (p==2139/tcp) || (p==2147/tcp) || (p==2334/tcp) || (p==2392/tcp) || (p==2478/tcp) ||
      (p==2821/tcp) || (p==3113/tcp) || (p==3207/tcp) || (p==3799/tcp) || (p==3810/tcp) || (p==3871/tcp) ||
      (p==3833/tcp) || (p==4032/tcp) || (p==4129/tcp) || (p==5067/tcp) || (p==5635/tcp) || (p==6268/tcp) ||
      (p==6269/tcp) || (p==7004/tcp) || (p==7847/tcp) || (p==9002/tcp) || (p==19194/tcp) || (p==27999/tcp))
    return "auth";
  else if (p==179/tcp)
    return "bgp";
  else if (p==53/tcp)
    return "domain";
  else if (p==7/tcp)
    return "echo";
  else if (p==512/tcp)
    return "exec";
  else if (p==79/tcp)
    return "finger";
  else if (p==21/tcp)
    return "ftp";
  else if (p==20/tcp)
    return "ftp_data";
  else if (p==101/tcp)
    return "hotnames";
  else if (p==80/tcp || p==8008/tcp || p==8080/tcp)
    return "http";
  else if (p==2784/tcp)
    return "http_2784";
  else if (p==443/tcp)
    return "http_443";
  else if (p==8001/tcp)
    return "http_8001";
  else if (p==5813/tcp)
    return "icmp";
  else if (p==143/tcp || p==993/tcp)
    return "imap4";
  else if (p==102/tcp || p==309/tcp)
    return "iso_tsap";
  else if (p==389/tcp || p==636/tcp)
    return "ldap";
  else if (p==513/tcp)
    return "login";
  else if (p==1911/tcp)
    return "mtp";
  else if (p==15/tcp)
    return "netstat";
  else if (p==109/tcp)
    return "pop_2";
  else if (p==110/tcp)
    return "pop_3";
  else if (p==514/tcp)
    return "shell";
  else if (p==25/tcp)
    return "smtp";
  else if (p==22/tcp)
    return "ssh";
  else if (p==11/tcp)
    return "systat";
  else if (p==23/tcp)
    return "telnet";
  else
    return "other";
  
}

########################## TCP ##############################
function record_connectionTCP(c: connection){
    local startTime : string = fmt ("%.6f", c$start_time-6*60min);
    local orig_h : addr = c$id$orig_h;
    local resp_h : addr = c$id$resp_h;
    local orig_p : port = c$id$orig_p;
    local resp_p : port = c$id$resp_p;
    
    if ([startTime, orig_h, orig_p, resp_h, resp_p] !in konexioaktcp)
    {
      local empty_record: konexioa;
      konexioaktcp[startTime, orig_h, orig_p, resp_h, resp_p] = empty_record;  

      ++num_conn;
      konexioaktcp[startTime, orig_h, orig_p, resp_h, resp_p]$num_conn = num_conn;
    }  
    
    konexioaktcp[startTime, orig_h, orig_p, resp_h, resp_p]$duration = fmt("%.6f", c$duration);
  konexioaktcp[startTime, orig_h, orig_p, resp_h, resp_p]$flag = conn_state(c, "tcp"); 
  konexioaktcp[startTime, orig_h, orig_p, resp_h, resp_p]$service = service_name(resp_p);
    konexioaktcp[startTime, orig_h, orig_p, resp_h, resp_p]$src_bytes = fmt("%d", c$orig$size);
    konexioaktcp[startTime, orig_h, orig_p, resp_h, resp_p]$dst_bytes = fmt("%d", c$resp$size); 
}

event new_connection(c: connection){
  local trans : string = fmt("%s", get_port_transport_proto(c$id$resp_p));
  if(trans=="tcp"){ 
      record_connectionTCP(c);
  }
}

event connection_state_remove(c: connection){
  local trans : string = fmt("%s", get_port_transport_proto(c$id$resp_p));  
  if (trans == "tcp"){  
      record_connectionTCP(c);
  }
}

event tcp_packet (c: connection, is_orig: bool, flags: string, seq: count, ack: count, len: count, payload: string){
  local startTime : string = fmt ("%.6f", c$start_time-6*60min);
  local orig_h : addr = c$id$orig_h;
  local resp_h : addr = c$id$resp_h;
  local orig_p : port = c$id$orig_p;
  local resp_p : port = c$id$resp_p;
  
  record_connectionTCP(c);

  if (konexioaktcp[startTime, orig_h, orig_p, resp_h, resp_p]$fitxSortuak == F){
      konexioaktcp[startTime, orig_h, orig_p, resp_h, resp_p]$fitxSortuak = T;
  }

  konexioaktcp[startTime, orig_h, orig_p, resp_h, resp_p]$payDu = T;
}

################# UDP #########################
redef udp_content_deliver_all_orig = T;
redef udp_content_deliver_all_resp = T;
event udp_contents(u: connection, is_orig: bool, contents: string){
  local startTime : string = fmt ("%.6f", u$start_time-6*60min);
  local duration : string = fmt ("%.6f", u$duration);
  local orig_h : addr = u$id$orig_h;
  local resp_h : addr = u$id$resp_h;
  local orig_p : port = u$id$orig_p;
  local resp_p : port = u$id$resp_p;
  if ([startTime, duration, orig_h, orig_p, resp_h, resp_p] !in konexioak){
      local empty_record: konexioa;
      konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p] = empty_record;

      ++num_conn;
      konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$num_conn = num_conn;
  }
  
  if ([startTime, orig_h, orig_p, resp_h, resp_p] !in byteak){
    local empty_byte: byte;
    byteak[startTime, orig_h, orig_p, resp_h, resp_p] = empty_byte;
  }

  konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$protokoloa = "udp";
  konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$flag = conn_state(u, "udp");
  konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$service = service_name(resp_p);
  
  if (is_orig){
      konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$isOrig = T;
      konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$src_bytes = 
        fmt("%d", u$orig$size-byteak[startTime, orig_h, orig_p, resp_h, resp_p]$src_bytes);
      konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$dst_bytes = "0";
    byteak[startTime, orig_h, orig_p, resp_h, resp_p]$src_bytes = u$orig$size;
      konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$payDu = T;
  }
  else{
    konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$isOrig = F;
      konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$dst_bytes = 
        fmt("%d", u$resp$size-byteak[startTime, orig_h, orig_p, resp_h, resp_p]$dst_bytes);
      konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$src_bytes = "0";
      byteak[startTime, orig_h, orig_p, resp_h, resp_p]$dst_bytes = u$resp$size;
      konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$payDu = T;
  }
}

################# ICMP ########################
function record_connectionICMP(c: connection){
  local startTime : string = fmt ("%.6f", c$start_time-6*60min);
  local duration : string = fmt ("%.6f", c$duration);
  local orig_h : addr = c$id$orig_h;
  local resp_h : addr = c$id$resp_h;
  local orig_p : port = c$id$orig_p;
  local resp_p : port = c$id$resp_p;
  if ([startTime, duration, orig_h, orig_p, resp_h, resp_p] !in konexioak){
      local empty_record: konexioa;
      konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p] = empty_record;
    
      ++num_conn;
      konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$num_conn = num_conn;
  }
  konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$service = service_name(resp_p);
}

event icmp_echo_request(c: connection, icmp: icmp_conn, id: count, seq: count, payload: string){
  local startTime : string = fmt ("%.6f", c$start_time-6*60min);
  local duration : string = fmt ("%.6f", c$duration);
  local orig_h : addr = c$id$orig_h;
  local resp_h : addr = c$id$resp_h;
  local orig_p : port = c$id$orig_p;
  local resp_p : port = c$id$resp_p;

  record_connectionICMP(c);

  if ([startTime, orig_h, orig_p, resp_h, resp_p] !in byteak){ 
      local empty_byte: byte;
      byteak[startTime, orig_h, orig_p, resp_h, resp_p] = empty_byte;
  }
  
  konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$isOrig = T;
  konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$protokoloa = "icmp";
  konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$flag = conn_state(c, "icmp");

  konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$src_bytes = 
      fmt("%d", c$orig$size-byteak[startTime, orig_h, orig_p, resp_h, resp_p]$src_bytes);
  konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$dst_bytes = "0";
  byteak[startTime, orig_h, orig_p, resp_h, resp_p]$src_bytes = c$orig$size;
  
  konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$orig_p = fmt("%d", icmp$itype);
  konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$resp_p = fmt("%d", icmp$icode);
  konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$orig_h = fmt("%s", icmp$orig_h);
  konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$resp_h = fmt("%s", icmp$resp_h);
 
  konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$payDu = T;
}

event icmp_echo_reply(c: connection, icmp: icmp_conn, id: count, seq: count, payload: string){
  local startTime : string = fmt ("%.6f", c$start_time-6*60min);
  local duration : string = fmt ("%.6f", c$duration);
  local orig_h : addr = c$id$orig_h;
  local resp_h : addr = c$id$resp_h;
  local orig_p : port = c$id$orig_p;
  local resp_p : port = c$id$resp_p;

  record_connectionICMP(c);

  if ([startTime, orig_h, orig_p, resp_h, resp_p] !in byteak){
      local empty_byte: byte;
      byteak[startTime, orig_h, orig_p, resp_h, resp_p] = empty_byte;
  }

  konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$isOrig = F;
  konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$protokoloa = "icmp";
  konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$flag = conn_state(c, "icmp");

  konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$dst_bytes = 
      fmt("%d", c$resp$size-byteak[startTime, orig_h, orig_p, resp_h, resp_p]$dst_bytes);
  konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$src_bytes = "0";
  byteak[startTime, orig_h, orig_p, resp_h, resp_p]$dst_bytes = c$resp$size;
  
  konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$orig_p = fmt("%d", icmp$itype);
  konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$resp_p = fmt("%d", icmp$icode);
  konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$orig_h = fmt("%s", icmp$orig_h);
  konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$resp_h = fmt("%s", icmp$resp_h);

  konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$payDu = T;
}

event icmp_unreachable(c: connection, icmp: icmp_conn, code: count, context: icmp_context){
  local startTime : string = fmt ("%.6f", c$start_time-6*60min);
  local duration : string = fmt ("%.6f", c$duration);
  local orig_h : addr = c$id$orig_h;
  local resp_h : addr = c$id$resp_h;
  local orig_p : port = c$id$orig_p;
  local resp_p : port = c$id$resp_p;

  record_connectionICMP(c);

  if ([startTime, orig_h, orig_p, resp_h, resp_p] !in byteak){
      local empty_byte: byte;
      byteak[startTime, orig_h, orig_p, resp_h, resp_p] = empty_byte;
  }

  konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$protokoloa = "icmp";
  konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$flag = conn_state(c, "icmp");
  
  konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$src_bytes =
    fmt("%d", c$orig$size-byteak[startTime, orig_h, orig_p, resp_h, resp_p]$src_bytes);
  konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$dst_bytes = "0";
  byteak[startTime, orig_h, orig_p, resp_h, resp_p]$src_bytes = c$orig$size;
  
  konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$orig_p = fmt("%d", icmp$itype);
  konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$resp_p = fmt("%d", icmp$icode);
  konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$orig_h = fmt("%s", icmp$orig_h);
  konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$resp_h = fmt("%s", icmp$resp_h);

  konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$payDu = T;
}

event icmp_time_exceeded(c: connection, icmp: icmp_conn, code: count, context: icmp_context)
{
  local startTime : string = fmt ("%.6f", c$start_time-6*60min);
  local duration : string = fmt ("%.6f", c$duration);
  local orig_h : addr = c$id$orig_h;
  local resp_h : addr = c$id$resp_h;
  local orig_p : port = c$id$orig_p;
  local resp_p : port = c$id$resp_p;

  record_connectionICMP(c);

  if ([startTime, orig_h, orig_p, resp_h, resp_p] !in byteak){
      local empty_byte: byte;
      byteak[startTime, orig_h, orig_p, resp_h, resp_p] = empty_byte;
  }

  konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$protokoloa = "icmp";
  konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$flag = conn_state(c, "icmp");

  konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$src_bytes =
    fmt("%d", c$orig$size-byteak[startTime, orig_h, orig_p, resp_h, resp_p]$src_bytes);
  konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$dst_bytes = "0";
  byteak[startTime, orig_h, orig_p, resp_h, resp_p]$src_bytes = c$orig$size;

  konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$orig_p = fmt("%d", icmp$itype);
  konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$resp_p = fmt("%d", icmp$icode);
  konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$orig_h = fmt("%s", icmp$orig_h);
  konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$resp_h = fmt("%s", icmp$resp_h);
  
  konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$payDu = T;
}

#Amaitzean konexio guztiak idatzi
event zeek_done()
{
  local land : count;
  local root_shell : count;
  local is_hot_login : count;
  local is_guest_login : count;
  #TCP
  for ([startTimet, orig_ht, orig_pt, resp_ht, resp_pt] in konexioaktcp){
    land = (orig_pt == resp_pt && orig_ht == resp_ht) ? 1 : 0;
    root_shell = (konexioaktcp[startTimet, orig_ht, orig_pt, resp_ht, resp_pt]$root_shell_num>0) ? 1 : 0;
    is_hot_login = (konexioaktcp[startTimet, orig_ht, orig_pt, resp_ht, resp_pt]$is_hot_login > 0) ? 1 : 0;
    is_guest_login = (konexioaktcp[startTimet, orig_ht, orig_pt, resp_ht, resp_pt]$is_guest_login > 0) ? 1 : 0;
    print fmt("%d %s %d %d %s %s %s %s %s %s %s %s %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d",
      konexioaktcp[startTimet, orig_ht, orig_pt, resp_ht, resp_pt]$num_conn, 
      startTimet, 
      orig_pt, 
      resp_pt, 
      orig_ht, 
      resp_ht, 
      konexioaktcp[startTimet, orig_ht, orig_pt, resp_ht, resp_pt]$duration, 
      "tcp",
    konexioaktcp[startTimet, orig_ht, orig_pt, resp_ht, resp_pt]$service,
        konexioaktcp[startTimet, orig_ht, orig_pt, resp_ht, resp_pt]$flag,
        konexioaktcp[startTimet, orig_ht, orig_pt, resp_ht, resp_pt]$src_bytes,
        konexioaktcp[startTimet, orig_ht, orig_pt, resp_ht, resp_pt]$dst_bytes, 
        land, 
        konexioaktcp[startTimet, orig_ht, orig_pt, resp_ht, resp_pt]$wrong_fragment,
        konexioaktcp[startTimet, orig_ht, orig_pt, resp_ht, resp_pt]$urg,
        konexioaktcp[startTimet, orig_ht, orig_pt, resp_ht, resp_pt]$hot,
        konexioaktcp[startTimet, orig_ht, orig_pt, resp_ht, resp_pt]$num_failed_logins,
        konexioaktcp[startTimet, orig_ht, orig_pt, resp_ht, resp_pt]$logged_in,
        konexioaktcp[startTimet, orig_ht, orig_pt, resp_ht, resp_pt]$num_compromised, 
        root_shell,
        konexioaktcp[startTimet, orig_ht, orig_pt, resp_ht, resp_pt]$su_attempted,
        konexioaktcp[startTimet, orig_ht, orig_pt, resp_ht, resp_pt]$num_root,
        konexioaktcp[startTimet, orig_ht, orig_pt, resp_ht, resp_pt]$num_file_creations,
        konexioaktcp[startTimet, orig_ht, orig_pt, resp_ht, resp_pt]$num_shells,
        konexioaktcp[startTimet, orig_ht, orig_pt, resp_ht, resp_pt]$num_access_files,
        konexioaktcp[startTimet, orig_ht, orig_pt, resp_ht, resp_pt]$num_outbound_cmds, 
        is_hot_login, 
        is_guest_login);

  }
  #UDP & ICMP
  for ([startTime, duration, orig_h, orig_p, resp_h, resp_p] in konexioak){
      land = (orig_p == resp_p && orig_h == resp_h) ? 1 : 0;
      root_shell = (konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$root_shell_num>0) ? 1 : 0;
      is_hot_login = (konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$is_hot_login > 0) ? 1 : 0;
      is_guest_login = (konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$is_guest_login > 0) ? 1 : 0;
    #icmp
    if(konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$protokoloa == "icmp"){
      print fmt("%d %s %s %s %s %s %s %s %s %s %s %s %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d",
        konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$num_conn, 
        startTime, 
        konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$orig_p, 
        konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$resp_p, 
        konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$orig_h, 
        konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$resp_h,
        duration, 
        "icmp", 
        konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$service,
      konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$flag,
      konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$src_bytes, 
      konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$dst_bytes, 
      land,
    konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$wrong_fragment,
    konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$urg,
    konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$hot,
      konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$num_failed_logins,
      konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$logged_in,
    konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$num_compromised, 
    root_shell,
    konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$su_attempted,
    konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$num_root,
    konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$num_file_creations,  
    konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$num_shells,
    konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$num_access_files,
    konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$num_outbound_cmds, 
    is_hot_login, 
    is_guest_login);
  }
  #udp
  else if (konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$protokoloa == "udp"){
      print fmt("%d %s %d %d %s %s %s %s %s %s %s %s %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d",
        konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$num_conn, 
        startTime,
      orig_p, 
      resp_p, 
      orig_h, 
      resp_h, 
      duration, 
      "udp",
    konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$service,
    konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$flag,
    konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$src_bytes,
    konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$dst_bytes, 
    land, 
    konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$wrong_fragment,
    konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$urg,
    konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$hot,
    konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$num_failed_logins,
    konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$logged_in,
    konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$num_compromised, 
    root_shell,
    konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$su_attempted,
    konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$num_root,
    konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$num_file_creations,
    konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$num_shells,
    konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$num_access_files,
    konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$num_outbound_cmds, 
    is_hot_login, 
    is_guest_login);
    }
  }
}

################ PAYLOAD (TCP,UDP,ICMP) ########################
event packet_contents(c: connection, contents: string){
  local startTime : string = fmt ("%.6f", c$start_time-6*60min); 
  local duration : string = fmt ("%.6f", c$duration);
  local orig_h : addr = c$id$orig_h;
  local resp_h : addr = c$id$resp_h;
  local orig_p : port = c$id$orig_p;
  local resp_p : port = c$id$resp_p; 
 
  local trans : string = fmt("%s", get_port_transport_proto(c$id$resp_p));
  local empty_record : konexioa;
 
  if (trans=="tcp"){
      if ([startTime, orig_h, orig_p, resp_h, resp_p] !in konexioaktcp){
        konexioaktcp[startTime, orig_h, orig_p, resp_h, resp_p] = empty_record;
        ++num_conn;
        konexioaktcp[startTime, orig_h, orig_p, resp_h, resp_p]$num_conn = num_conn;
      }

    konexioaktcp[startTime, orig_h, orig_p, resp_h, resp_p]$duration = fmt("%.6f", c$duration);  
    konexioaktcp[startTime, orig_h, orig_p, resp_h, resp_p]$flag = conn_state(c, "tcp");
    konexioaktcp[startTime, orig_h, orig_p, resp_h, resp_p]$service = service_name(resp_p);
    konexioaktcp[startTime, orig_h, orig_p, resp_h, resp_p]$src_bytes = fmt("%s", c$orig$size);
    konexioaktcp[startTime, orig_h, orig_p, resp_h, resp_p]$dst_bytes = fmt("%s", c$resp$size);
  }
  else{
    if ([startTime, duration, orig_h, orig_p, resp_h, resp_p] !in konexioak){ 
        konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p] = empty_record;

        ++num_conn;
        konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$num_conn = num_conn;
    }

    if ([startTime, orig_h, orig_p, resp_h, resp_p] !in byteak){
        local empty_byte: byte;
        byteak[startTime, orig_h, orig_p, resp_h, resp_p] = empty_byte;
    }
  
    if(konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$payDu==F){
      if (trans=="icmp"){
        konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$protokoloa = "icmp";
          konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$flag = conn_state(c, "icmp");
          konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$service = service_name(resp_p);
          konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$orig_p = fmt("%d", c$id$orig_p);
          konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$resp_p = fmt("%d", c$id$resp_p);
          konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$orig_h = fmt("%s", c$id$orig_h);
          konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$resp_h = fmt("%s", c$id$resp_h);
        }
      else if (trans=="udp"){
          konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$protokoloa = "udp";
          konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$flag = conn_state(c, "udp"); 
      }  
  
        if(konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$isOrig){
          konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$src_bytes = 
            fmt("%d", c$orig$size-byteak[startTime, orig_h, orig_p, resp_h, resp_p]$src_bytes);
          konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$dst_bytes = "0";
        byteak[startTime, orig_h, orig_p, resp_h, resp_p]$src_bytes = c$orig$size;
        }
        else{
          konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$src_bytes = "0";
          konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$dst_bytes = 
              fmt("%d", c$orig$size-byteak[startTime, orig_h, orig_p, resp_h, resp_p]$dst_bytes);
          byteak[startTime, orig_h, orig_p, resp_h, resp_p]$dst_bytes = c$resp$size;
        }
  #    konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$payload = contents;
    }
  }
}

################### GAINERAKO ALDAGAIAK LORTU ##########################
function konexioaSortu(c: connection){
  local trans : string = fmt("%s", get_port_transport_proto(c$id$resp_p));
  local startTime : string = fmt("%.6f", c$start_time-6*60min);
  local duration : string = fmt("%.6f", c$duration);
  local orig_h : addr = c$id$orig_h;
  local resp_h : addr = c$id$resp_h;
  local orig_p : port = c$id$orig_p;
  local resp_p : port = c$id$resp_p;

  local empty_record : konexioa;
  if (trans=="tcp"){
      if ([startTime, orig_h, orig_p, resp_h, resp_p] !in konexioaktcp){
        konexioaktcp[startTime, orig_h, orig_p, resp_h, resp_p] = empty_record;
  
        ++num_conn;
        konexioaktcp[startTime, orig_h, orig_p, resp_h, resp_p]$num_conn = num_conn;
        konexioaktcp[startTime, orig_h, orig_p, resp_h, resp_p]$duration = fmt("%.6f", c$duration);
        konexioaktcp[startTime, orig_h, orig_p, resp_h, resp_p]$flag = conn_state(c, "tcp");
        konexioaktcp[startTime, orig_h, orig_p, resp_h, resp_p]$service = service_name(resp_p);
        konexioaktcp[startTime, orig_h, orig_p, resp_h, resp_p]$src_bytes = fmt("%d", c$orig$size);
        konexioaktcp[startTime, orig_h, orig_p, resp_h, resp_p]$dst_bytes = fmt("%d", c$resp$size);
      }
  }
  else{
      if ([startTime, duration, orig_h, orig_p, resp_h, resp_p] !in konexioak){
        konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p] = empty_record;

        ++num_conn;
        konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$num_conn = num_conn;
      }

    if(konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$payDu==F){
        if (trans=="icmp"){
          konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$protokoloa = "icmp";
          konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$flag = conn_state(c, "icmp");
          konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$service = service_name(resp_p);
          konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$orig_p = fmt("%d", c$id$orig_p);
          konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$resp_p = fmt("%d", c$id$resp_p);
          konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$orig_h = fmt("%s", c$id$orig_h);
          konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$resp_h = fmt("%s", c$id$resp_h);
        }
        else if (trans=="udp"){
          konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$protokoloa = "udp";
          konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$flag = conn_state(c, "udp");
          konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$service = service_name(resp_p); 
        }
    }
  }
}

#logged_in
function logged_in(c: connection){
  local trans : string = fmt("%s", get_port_transport_proto(c$id$resp_p));
  local startTime : string = fmt("%.6f", c$start_time-6*60min);
  local duration : string = fmt("%.6f", c$duration);
  local orig_h : addr = c$id$orig_h;
  local resp_h : addr = c$id$resp_h;
  local orig_p : port = c$id$orig_p;
  local resp_p : port = c$id$resp_p;
  
  konexioaSortu(c);

  if(trans=="tcp")
      konexioaktcp[startTime, orig_h, orig_p, resp_h, resp_p]$logged_in=1; 
  else
    konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$logged_in=1;
}

#host, guest
function inkrHotGuest(c: connection, username: string){
  local trans : string = fmt("%s", get_port_transport_proto(c$id$resp_p));
  local startTime : string = fmt("%.6f", c$start_time-6*60min);
  local duration : string = fmt("%.6f", c$duration);
  local orig_h : addr = c$id$orig_h;
  local resp_h : addr = c$id$resp_h;
  local orig_p : port = c$id$orig_p;
  local resp_p : port = c$id$resp_p;
  if (/[gG][uU][eE][sS][tT]/ in username ||
    /[aA][nN][oO][nN][yY][mM][oO][uU][sS]/ in username ||
    /[vV][iI][sS][iI][tT][oO][rR]/ in username ||
    /[a-zA-Z0-9]+@[a-zA-Z0-9]+\.[a-zA-Z0-9]+/ in username){
    if(trans=="tcp")
        ++konexioaktcp[startTime, orig_h, orig_p, resp_h, resp_p]$is_guest_login;
    else
      ++konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$is_guest_login;
  }
  if (/[rR][oO][oO][tT]/ in username ||
      /[aA][dD][mM]/ in username){
      if(trans=="tcp")
        ++konexioaktcp[startTime, orig_h, orig_p, resp_h, resp_p]$is_hot_login;
    else
      ++konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$is_hot_login;
  } 
}

#num_failed_logins
function num_failed_logins(c: connection){
  local trans : string = fmt("%s", get_port_transport_proto(c$id$resp_p));
  local startTime : string = fmt("%.6f", c$start_time-6*60min);
  local duration : string = fmt("%.6f", c$duration);
  local orig_h : addr = c$id$orig_h;
  local resp_h : addr = c$id$resp_h;
  local orig_p : port = c$id$orig_p;
  local resp_p : port = c$id$resp_p;
  if(trans=="tcp")
    ++konexioaktcp[startTime, orig_h, orig_p, resp_h, resp_p]$num_failed_logins;
  else
    ++konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$num_failed_logins;
}

#num_compromised
function not_found(c: connection, line: string){
  local trans : string = fmt("%s", get_port_transport_proto(c$id$resp_p));
  local startTime : string = fmt("%.6f", c$start_time-6*60min);
  local duration : string = fmt("%.6f", c$duration);
  local orig_h : addr = c$id$orig_h;
  local resp_h : addr = c$id$resp_h;
  local orig_p : port = c$id$orig_p;
  local resp_p : port = c$id$resp_p;
  if (/[nN][oO][tT] [fF][oO][uU][nN][dD]/ in line){
    if(trans=="tcp")
        ++konexioaktcp[startTime, orig_h, orig_p, resp_h, resp_p]$num_compromised;
      else
        ++konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$num_compromised;
  }
}

#num_root
function num_root(c: connection, user: string){
  local trans : string = fmt("%s", get_port_transport_proto(c$id$resp_p));
  local startTime : string = fmt("%.6f", c$start_time-6*60min);
  local duration : string = fmt("%.6f", c$duration);
  local orig_h : addr = c$id$orig_h;
  local resp_h : addr = c$id$resp_h;
  local orig_p : port = c$id$orig_p;
  local resp_p : port = c$id$resp_p;
  if(/[rR][oO][oO][tT]/ in user){
    if(trans=="tcp")
        ++konexioaktcp[startTime, orig_h, orig_p, resp_h, resp_p]$num_root;
    else
      ++konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$num_root;
  }
}

#num_rootInkr
function num_rootInkr(c: connection){
  local trans : string = fmt("%s", get_port_transport_proto(c$id$resp_p));
  local startTime : string = fmt("%.6f", c$start_time-6*60min);
  local duration : string = fmt("%.6f", c$duration);
  local orig_h : addr = c$id$orig_h;
  local resp_h : addr = c$id$resp_h;
  local orig_p : port = c$id$orig_p;
  local resp_p : port = c$id$resp_p;
  if(trans=="tcp")
      ++konexioaktcp[startTime, orig_h, orig_p, resp_h, resp_p]$num_root;
  else
    ++konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$num_root;
}

#root_shell_num
function root_shell(c: connection, user: string){
  local trans : string = fmt("%s", get_port_transport_proto(c$id$resp_p));
  local startTime : string = fmt("%.6f", c$start_time-6*60min);
  local duration : string = fmt("%.6f", c$duration);
  local orig_h : addr = c$id$orig_h;
  local resp_h : addr = c$id$resp_h;
  local orig_p : port = c$id$orig_p;
  local resp_p : port = c$id$resp_p;
  if(/[rR][oO][oO][tT]/ in user){
    if(trans=="tcp")
        ++konexioaktcp[startTime, orig_h, orig_p, resp_h, resp_p]$root_shell_num;
    else
      ++konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$root_shell_num;
  }
}

#num_file_creations
function num_file_creations(c: connection){
  local trans : string = fmt("%s", get_port_transport_proto(c$id$resp_p));
  local startTime : string = fmt("%.6f", c$start_time-6*60min);
  local duration : string = fmt("%.6f", c$duration);
  local orig_h : addr = c$id$orig_h;
  local resp_h : addr = c$id$resp_h;
  local orig_p : port = c$id$orig_p;
  local resp_p : port = c$id$resp_p;
  if(trans=="tcp")
    ++konexioaktcp[startTime, orig_h, orig_p, resp_h, resp_p]$num_file_creations;
  else
      ++konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$num_file_creations;
}

#hot
function hot(c: connection){
  local trans : string = fmt("%s", get_port_transport_proto(c$id$resp_p));
  local startTime : string = fmt("%.6f", c$start_time-6*60min);
  local duration : string = fmt("%.6f", c$duration);
  local orig_h : addr = c$id$orig_h;
  local resp_h : addr = c$id$resp_h;
  local orig_p : port = c$id$orig_p;
  local resp_p : port = c$id$resp_p;
  if(trans=="tcp")  
    ++konexioaktcp[startTime, orig_h, orig_p, resp_h, resp_p]$hot;
  else
    ++konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$hot;
}

#root_shell_num
function root_shell_num(c: connection){
  local trans : string = fmt("%s", get_port_transport_proto(c$id$resp_p));
  local startTime : string = fmt("%.6f", c$start_time-6*60min);
  local duration : string = fmt("%.6f", c$duration);
  local orig_h : addr = c$id$orig_h;
  local resp_h : addr = c$id$resp_h;
  local orig_p : port = c$id$orig_p;
  local resp_p : port = c$id$resp_p;
  if(trans=="tcp")
    ++konexioaktcp[startTime, orig_h, orig_p, resp_h, resp_p]$root_shell_num;
  else
    ++konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$root_shell_num;    
}

#outbound
function outbound (c: connection, command: string){
  local trans : string = fmt("%s", get_port_transport_proto(c$id$resp_p));
  local startTime : string = fmt("%.6f", c$start_time-6*60min);
  local duration : string = fmt("%.6f", c$duration);
  local orig_h : addr = c$id$orig_h;
  local resp_h : addr = c$id$resp_h;
  local orig_p : port = c$id$orig_p;
  local resp_p : port = c$id$resp_p;
  if (/[oO][uU][tT][bB][oO][uU][nN][dD]/ in command)
  if(trans=="tcp")
    ++konexioaktcp[startTime, orig_h, orig_p, resp_h, resp_p]$num_outbound_cmds;
  else
    ++konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$num_outbound_cmds;
}

event new_packet (c: connection, p: pkt_hdr){
  local trans : string = fmt("%s", get_port_transport_proto(c$id$resp_p));
  local startTime : string = fmt("%.6f", c$start_time-6*60min);
  local duration : string = fmt("%.6f", c$duration);
  local orig_h : addr = c$id$orig_h;
  local resp_h : addr = c$id$resp_h;
  local orig_p : port = c$id$orig_p;
  local resp_p : port = c$id$resp_p;

  konexioaSortu(c);

  #urgent
  if (get_port_transport_proto(c$id$resp_p) == tcp){
    if (p$tcp$flags >= 32){
      if (trans=="tcp")
        ++konexioaktcp[startTime, orig_h, orig_p, resp_h, resp_p]$urg;
      else
        ++konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$urg;
    }
  }
}

event login_input_line(c: connection, line: string){
  local trans : string = fmt("%s", get_port_transport_proto(c$id$resp_p));
  local startTime : string = fmt("%.6f", c$start_time-6*60min);
  local duration : string = fmt("%.6f", c$duration);
  local orig_h : addr = c$id$orig_h;
  local resp_h : addr = c$id$resp_h;
  local orig_p : port = c$id$orig_p;
  local resp_p : port = c$id$resp_p;
  
  konexioaSortu(c);
  
  #su_attempted
  if ( /su -/ in line){
    if(trans=="tcp")
      ++konexioaktcp[startTime, orig_h, orig_p, resp_h, resp_p]$su_attempted;
    else
      ++konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$su_attempted;    
  }
  #num_access_files
  if ( /cat \// in line ||
       ((/vi / in line) && !(/.tex/ in line))||
       ((/rm / in line) && !(/.tex/ in line)) ){
    if(trans=="tcp")
      ++konexioaktcp[startTime, orig_h, orig_p, resp_h, resp_p]$num_access_files;
    else
      ++konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$num_access_files;
  }
  
  #is_hot_login
  if (/su - root/ in line ||
    /^[0-9]*root/ in line){
      if(trans=="tcp")
        ++konexioaktcp[startTime, orig_h, orig_p, resp_h, resp_p]$is_hot_login;
      else
        ++konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$is_hot_login;
  }
    
  #hot
  #sistemako direktorioetara
  if ( (/cd / in line) && !(/dir/ in line)){
    hot(c);
  }
    #programak sortzea
  if (/gcc / in line ||
      /g++ / in line){
    num_file_creations(c);      
    hot(c);
  }
    #programak exekutatzea
  if(/^\.\// in line){
    hot(c);
  }
  if(/^\/tmp\/[0-9]+/ in line){
    hot(c);
  }

  if(/a.out/ in line ||
     /auditd/ in line ||
     /automountd/ in line ||
     /cron/ in line ||
     /find/ in line ||
     /fsck/ in line ||
     /ftp/ in line ||
     /in.comsat/ in line ||
     /inetd/ in line ||
     /in.ftpd/ in line ||
     /init/ in line ||
     /in.telnetd/ in line ||
     /kerbd/ in line ||
     /keyserv/ in line ||
     /lockd/ in line ||
     /login/ in line ||
     /lp.cat/ in line ||
     /lpNet/ in line ||
     /lpsched/ in line ||
     /lp.tell/ in line ||
     /lynx/ in line ||
     /mail/ in line ||
     /man/ in line ||
     /mlp/ in line ||
     /more/ in line ||
     /netscape/ in line ||
     /nscd/ in line ||
     /primes/ in line ||
     /sendmail/ in line ||
     /sh/ in line ||
     /sleep/ in line ||
     /sshd/ in line ||
     /statd/ in line || 
     /syslogd/ in line ||
     /tcsh/ in line ||
     /telnet/ in line ||
     /tex/ in line ||
     /top/ in line ||
     /ttymon/ in line ||
     /vi/ in line ||
     /vold/ in line ||
     /xntpd/ in line){
      hot(c);
  }
  #num_file_creations
  if(/cp[ \t]+/ in line ||
    /mv[ \t]+/ in line ||
    /cat >/ in line){
    num_file_creations(c);
  }

  inkrHotGuest(c,line);
}

event login_output_line(c: connection, line: string){
  local trans : string = fmt("%s", get_port_transport_proto(c$id$resp_p));
  local startTime : string = fmt("%.6f", c$start_time-6*60min);
  local duration : string = fmt("%.6f", c$duration);
  local orig_h : addr = c$id$orig_h;
  local resp_h : addr = c$id$resp_h;
  local orig_p : port = c$id$orig_p;
  local resp_p : port = c$id$resp_p;
  
  konexioaSortu(c);

  #num_failed_logins
  if (/Login incorrect/ in line){
    num_failed_logins(c);
  }
  
  #num_root
  if (/^root@/ in line){
    if(trans=="tcp")
        ++konexioaktcp[startTime, orig_h, orig_p, resp_h, resp_p]$num_root;
    else
        ++konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$num_root;
    root_shell_num(c);
  }
  
  if (/su - root/ in line){
    if(trans=="tcp")
      konexioaktcp[startTime, orig_h, orig_p, resp_h, resp_p]$rootDa = T;
    else
      konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$rootDa = T;
  }
  if (/^Sun Microsystems/ in line){
      if(trans=="tcp"){
        if (konexioaktcp[startTime, orig_h, orig_p, resp_h, resp_p]$rootDa){
          ++konexioaktcp[startTime, orig_h, orig_p, resp_h, resp_p]$root_shell_num;
          konexioaktcp[startTime, orig_h, orig_p, resp_h, resp_p]$rootDa = F;
        }
      }
      else{
        if (konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$rootDa){
          ++konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$root_shell_num;
          konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$rootDa = F;
      }
    }
  }
  
  #num_shells
  if (/^Last login:/ in line){
    if(trans=="tcp")
        ++konexioaktcp[startTime, orig_h, orig_p, resp_h, resp_p]$num_shells;
    else
        ++konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$num_shells;
  }
  
  #num_file_creations
  if(/\[New file\]/ in line)
    num_file_creations(c);
  
  not_found(c,line);
}

#login okerra
event login_failure(c: connection, user: string, client_user: string, password: string, line: string){
  konexioaSortu(c);
  num_failed_logins(c);
}

#login zuzena
event login_success(c: connection, user: string, client_user: string, password: string, line: string){
  konexioaSortu(c);
  logged_in(c);
  inkrHotGuest(c,user);
}

event login_terminal(c: connection, terminal: string){
  konexioaSortu(c);
  logged_in(c);
  inkrHotGuest(c,terminal);
}

event login_display(c: connection, display: string){
  konexioaSortu(c);
  logged_in(c);
  inkrHotGuest(c,display);
}

event login_prompt(c: connection, prompt: string){
  konexioaSortu(c);
  logged_in(c);
  inkrHotGuest(c,prompt);
  root_shell(c, prompt);
}

#signatureak
event ssh_signature_found(c: connection, is_orig: bool){
  konexioaSortu(c);
  logged_in(c);
}

event telnet_signature_found(c: connection, is_orig: bool, len: count){
  konexioaSortu(c);
  logged_in(c);
}

event rlogin_signature_found(c: connection, is_orig: bool, num_null: count, len: count){
  konexioaSortu(c);
  logged_in(c);
}

event root_backdoor_signature_found(c: connection){
  konexioaSortu(c);
  logged_in(c);
}

event ftp_signature_found(c: connection){
  konexioaSortu(c);
  logged_in(c);
}

event napster_signature_found(c: connection){
  konexioaSortu(c);
  logged_in(c);
}

event gnutella_signature_found(c: connection){
  konexioaSortu(c);
  logged_in(c);
}

event kazaa_signature_found(c: connection){
  konexioaSortu(c);
  logged_in(c);
}

event http_signature_found(c: connection){
  konexioaSortu(c);
  logged_in(c);
}

event http_proxy_signature_found(c: connection){
  konexioaSortu(c);
  logged_in(c);
}

event smtp_signature_found(c: connection){
  konexioaSortu(c);
  logged_in(c);
}

event irc_signature_found(c: connection){
  konexioaSortu(c);
  logged_in(c);
}

event gaobot_signature_found (c: connection){
  konexioaSortu(c);
  logged_in(c);
}

#zerbitzu konkretuak, usr dutenak
event finger_request(c: connection, full: bool, username: string, hostname: string){
  konexioaSortu(c);
  inkrHotGuest(c,username);
  num_root(c,username);
}

event ident_reply(c: connection, lport: port, rport: port, user_id: string, system: string){
  konexioaSortu(c);
  inkrHotGuest(c,user_id);
  num_root(c,user_id);
}

event rsh_reply(c: connection, client_user: string, server_user: string, line: string){
  konexioaSortu(c);
  inkrHotGuest(c,client_user);
  inkrHotGuest(c,server_user);
  num_root(c,client_user);
  num_root(c,server_user);
}

event pop3_login_success(c: connection, is_orig: bool, user: string, password: string){
  konexioaSortu(c);
  inkrHotGuest(c,user);
  num_root(c,user);
}

event pop3_login_failure(c: connection, is_orig: bool, user: string, password: string){
  konexioaSortu(c);
  inkrHotGuest(c,user);
  num_root(c,user);
}

event irc_who_line(c: connection, is_orig: bool, target_nick: string, channel: string, user: string, host: string, server: string, nick: string, params: string, hops: count, real_name: string){
  konexioaSortu(c);
  inkrHotGuest(c,user);
  num_root(c,user);
}

event irc_whois_message(c: connection, is_orig: bool, server: string, users: string){
  konexioaSortu(c);
  inkrHotGuest(c,users);
  num_root(c,users);
}

event irc_whois_user_line(c: connection, is_orig: bool, nick: string, user: string, host: string, real_name: string){
  konexioaSortu(c);
  inkrHotGuest(c,user);
  num_root(c,user);
}

event irc_oper_message(c: connection, is_orig: bool, user: string, password: string){
  konexioaSortu(c);
  inkrHotGuest(c,user);
  num_root(c,user);
}

event irc_kick_message(c: connection, is_orig: bool, prefix: string, chans: string, users: string, comment: string){
  konexioaSortu(c);
  inkrHotGuest(c,users);
  num_root(c,users);
}

event irc_names_info(c: connection, is_orig: bool, c_type: string, channel: string, users: string_set){
  konexioaSortu(c);
  for([erab] in users){
    inkrHotGuest(c,erab);
    num_root(c,erab);
  }
}

#outbound
event ftp_request(c: connection, command: string, arg: string){
  konexioaSortu(c);
  outbound(c,command);
}

##################### WEIRD ##############################
global wrong_fragment_set: set[string] = {
    ["bad_ICMP_checksum"],
    ["bad_TCP_checksum"],
    ["bad_UDP_checksum"],
};

event conn_weird (name: string, c: connection, addl: string){
  local trans : string = fmt("%s", get_port_transport_proto(c$id$resp_p));
  local startTime : string = fmt("%.6f", c$start_time-6*60min);
  local duration : string = fmt("%.6f", c$duration);
  local orig_h : addr = c$id$orig_h;
  local resp_h : addr = c$id$resp_h;
  local orig_p : port = c$id$orig_p;
  local resp_p : port = c$id$resp_p;

  konexioaSortu(c);
  
  if (name in wrong_fragment_set){
    if(trans=="tcp")
      ++konexioaktcp[startTime, orig_h, orig_p, resp_h, resp_p]$wrong_fragment;
    else
      konexioak[startTime, duration, orig_h, orig_p, resp_h, resp_p]$wrong_fragment=1;
  }
}
