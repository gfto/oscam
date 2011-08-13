#include "globals.h"

#define CS_VERSION_X  CS_VERSION

static int8_t monitor_check_ip()
{
	int32_t ok=0;
	struct s_client *cur_cl = cur_client();
	
	if (cur_cl->auth) return 0;
	ok = check_ip(cfg.mon_allowed, cur_cl->ip);
	if (!ok)
	{
		cs_auth_client(cur_cl, (struct s_auth *)0, "invalid ip");
		return -1;
	}
	return 0;
}

static int8_t monitor_auth_client(char *usr, char *pwd)
{
	struct s_auth *account;
	struct s_client *cur_cl = cur_client();
	
	if (cur_cl->auth) return 0;
	if ((!usr) || (!pwd))
	{
		cs_auth_client(cur_cl, (struct s_auth *)0, NULL);
		return -1;
	}
	for (account=cfg.account, cur_cl->auth=0; (account) && (!cur_cl->auth);)
	{
		if (account->monlvl)
			cur_cl->auth=!(strcmp(usr, account->usr) | strcmp(pwd, account->pwd));
		if (!cur_cl->auth)
			account=account->next;
	}
	if (!cur_cl->auth)
	{
		cs_auth_client(cur_cl, (struct s_auth *)0, "invalid account");
		return -1;
	}
	if (cs_auth_client(cur_cl, account, NULL))
		return -1;
	return 0;
}

static int32_t secmon_auth_client(uchar *ucrc)
{
	uint32_t crc;
	struct s_auth *account;
	struct s_client *cur_cl = cur_client();
	unsigned char md5tmp[MD5_DIGEST_LENGTH];
	
	if (cur_cl->auth)
	{
		int32_t s=memcmp(cur_cl->ucrc, ucrc, 4);
		if (s)
			cs_log("wrong user-crc or garbage !?");
		return(!s);
	}
	cur_cl->crypted=1;
	crc=(ucrc[0]<<24) | (ucrc[1]<<16) | (ucrc[2]<<8) | ucrc[3];
	for (account=cfg.account; (account) && (!cur_cl->auth); account=account->next)
		if ((account->monlvl) &&
				(crc==crc32(0L, MD5((unsigned char *)account->usr, strlen(account->usr), md5tmp), MD5_DIGEST_LENGTH)))
		{
			memcpy(cur_cl->ucrc, ucrc, 4);
			aes_set_key((char *)MD5((unsigned char *)account->pwd, strlen(account->pwd), md5tmp));
			if (cs_auth_client(cur_cl, account, NULL))
				return -1;
			cur_cl->auth=1;
		}
	if (!cur_cl->auth)
	{
		cs_auth_client(cur_cl, (struct s_auth *)0, "invalid user");
		return -1;
	}
	return(cur_cl->auth);
}

int32_t monitor_send_idx(struct s_client *cl, char *txt)
{
	int32_t l;
	unsigned char buf[256+32];
	if (!cl->udp_fd)
		return(-1);
	struct timespec req_ts;
	req_ts.tv_sec = 0;
	req_ts.tv_nsec = 500000;
	nanosleep (&req_ts, NULL);//avoid lost udp-pakkets
	if (!cl->crypted)
		return(sendto(cl->udp_fd, txt, strlen(txt), 0,
				(struct sockaddr *)&cl->udp_sa,
				sizeof(cl->udp_sa)));
	buf[0]='&';
	buf[9]=l=strlen(txt);
	l=boundary(4, l+5)+5;
	memcpy(buf+1, cl->ucrc, 4);
	cs_strncpy((char *)buf+10, txt, sizeof(buf)-10);
	uchar tmp[10];
	memcpy(buf+5, i2b_buf(4, crc32(0L, buf+10, l-10), tmp), 4);
	aes_encrypt_idx(cl, buf+5, l-5);
	return(sendto(cl->udp_fd, buf, l, 0,
			(struct sockaddr *)&cl->udp_sa,
			sizeof(cl->udp_sa)));
}

#define monitor_send(t) monitor_send_idx(cur_client(), t)

static int32_t monitor_recv(struct s_client * client, uchar *buf, int32_t l)
{
	int32_t n;
	uchar nbuf[3] = { 'U', 0, 0 };
	static int32_t bpos=0, res = 0;
	static uchar *bbuf=NULL;
	if (!bbuf)
	{
		bbuf = cs_malloc(&bbuf, l, 1);
	}
	if (bpos)
		memcpy(buf, bbuf, n=bpos);
	else
		n=recv_from_udpipe(buf);
	bpos=0;
	if (!n) return(buf[0]=0);
	if (buf[0]=='&')
	{
		int32_t bsize;
		if (n<21)	// 5+16 is minimum
		{
			cs_log("packet too small!");
			return(buf[0]=0);
		}
		res = secmon_auth_client(buf+1);
		if (res == -1) {
			cs_disconnect_client(client);
			return 0;
		}
		if (!res)
			return(buf[0]=0);
		aes_decrypt(buf+5, 16);
		bsize=boundary(4, buf[9]+5)+5;
		// cs_log("n=%d bsize=%d", n, bsize);
		if (n>bsize)
		{
			// cs_log("DO >>>> copy-back");
			memcpy(bbuf, buf+bsize, bpos=n-bsize);
			n=bsize;
			//write_to_pipe(client->fd_m2c, PIP_ID_UDP, (uchar*)&nbuf, sizeof(nbuf));
			add_job(client, ACTION_CLIENT_UDP, &nbuf, sizeof(nbuf));
		}
		else if (n<bsize)
		{
			cs_log("packet-size mismatch !");
			return(buf[0]=0);
		}
		aes_decrypt(buf+21, n-21);
		uchar tmp[10];
		if (memcmp(buf+5, i2b_buf(4, crc32(0L, buf+10, n-10), tmp), 4))
		{
			cs_log("CRC error ! wrong password ?");
			return(buf[0]=0);
		}
		n=buf[9];
		memmove(buf, buf+10, n);
	}
	else
	{
		uchar *p;
		if (monitor_check_ip() == -1) {
			cs_disconnect_client(client);
			return 0;
		}
		buf[n]='\0';
		if ((p=(uchar *)strchr((char *)buf, 10)) && (bpos=n-(p-buf)-1))
		{
			memcpy(bbuf, p+1, bpos);
			n=p-buf;
			//write_to_pipe(client->fd_m2c, PIP_ID_UDP, (uchar*)&nbuf, sizeof(nbuf));
			add_job(client, ACTION_CLIENT_UDP, &nbuf, sizeof(nbuf));
		}
	}
	buf[n]='\0';
	n=strlen(trim((char *)buf));
	if (n) client->last=time((time_t *) 0);
	return(n);
}

static void monitor_send_info(char *txt, int32_t last)
{
	static int32_t seq=0, counter=0;
	static char btxt[256] = {0};
	char buf[8];
	if (txt)
	{
		if (!btxt[0])
		{
			counter=0;
			txt[2]='B';
		}
		else
			counter++;
		snprintf(buf, sizeof(buf), "%03d", counter);
		memcpy(txt+4, buf, 3);
		txt[3]='0'+seq;
	}
	else
		if (!last)
			return;

	if (!last)
	{
		if (btxt[0]) monitor_send(btxt);
		cs_strncpy(btxt, txt, sizeof(btxt));
		return;
	}

	if (txt && btxt[0])
	{
		monitor_send(btxt);
		txt[2]='E';
		cs_strncpy(btxt, txt, sizeof(btxt));
	}
	else
	{
		if (txt)
			cs_strncpy(btxt, txt, sizeof(btxt));
		btxt[2]=(btxt[2]=='B') ? 'S' : 'E';
	}

	if (btxt[0])
	{
		monitor_send(btxt);
		seq=(seq+1)%10;
	}
	btxt[0]=0;
}

static char *monitor_client_info(char id, struct s_client *cl, char *sbuf){
	char channame[32];
	sbuf[0] = '\0';

	if (cl){
		char ldate[16], ltime[16], *usr;
		int32_t lsec, isec, con, cau, lrt =- 1;
		time_t now;
		struct tm lt;
		now=time((time_t)0);

		if	((cfg.mon_hideclient_to <= 0) ||
				(now-cl->lastecm < cfg.mon_hideclient_to) ||
				(now-cl->lastemm < cfg.mon_hideclient_to) ||
				(cl->typ != 'c'))
		{
			lsec = now - cl->login;
			isec = now - cl->last;
			usr = username(cl);
			if (cl->dup)
				con = 2;
			else
				if ((cl->tosleep) && (now-cl->lastswitch>cl->tosleep))
					con = 1;
				else
					con = 0;

			// no AU reader == 0 / AU ok == 1 / Last EMM > aulow == -1
			if(cl->typ == 'c' || cl->typ == 'p' || cl->typ == 'r') {

				if ((cl->typ == 'c' && !cl->aureader_list) ||
						((cl->typ == 'p' || cl->typ == 'r') && cl->reader->audisabled))
					cau = 0;

				else if ((now-cl->lastemm) / 60 > cfg.mon_aulow)
					cau = (-1);

				else
					cau = 1;

			} else {
				cau = 0;
			}

			if( cl->typ == 'r')
			{
				int32_t i;
				struct s_reader *rdr;
				for (i=0,rdr=first_active_reader; rdr ; rdr=rdr->next, i++)
					if (cl->reader == rdr)
						lrt=i;

				if( lrt >= 0 )
					lrt = 10 + cl->reader->card_status;
			}
			else
                lrt = cl->cwlastresptime;
			localtime_r(&cl->login, &lt);
			snprintf(ldate, sizeof(ldate), "%02d.%02d.%02d", lt.tm_mday, lt.tm_mon+1, lt.tm_year % 100);
			int32_t cnr=get_threadnum(cl);
			snprintf(ltime, sizeof(ldate), "%02d:%02d:%02d", lt.tm_hour, lt.tm_min, lt.tm_sec);
			snprintf(sbuf, 256, "[%c--CCC]%8X|%c|%d|%s|%d|%d|%s|%d|%s|%s|%s|%d|%04X:%04X|%s|%d|%d|%d|%d|%d|%d|%d|%d|%d|%d\n",
					id, cl->tid, cl->typ, cnr, usr, cau, cl->crypted,
					cs_inet_ntoa(cl->ip), cl->port, monitor_get_proto(cl),
					ldate, ltime, lsec, cl->last_caid, cl->last_srvid,
					get_servicename(cl, cl->last_srvid, cl->last_caid, channame), isec, con,
                                        cl->cwfound, cl->cwnot, cl->cwcache, cl->cwignored,
                                        cl->cwtout, cl->emmok, cl->emmnok, lrt);
		}
	}
	return(sbuf);
}

static void monitor_process_info(){
	time_t now = time((time_t)0);
	char sbuf[256];

	struct s_client *cl, *cur_cl = cur_client();
	
	for (cl=first_client; cl ; cl=cl->next) {
		if	((cfg.mon_hideclient_to <= 0) ||
				( now-cl->lastecm < cfg.mon_hideclient_to) ||
				( now-cl->lastemm < cfg.mon_hideclient_to) ||
				( cl->typ != 'c')){
			if ((cur_cl->monlvl < 2) && (cl->typ != 's')) {
					if ((cur_cl->account && cl->account && strcmp(cur_cl->account->usr, cl->account->usr)) ||
							((cl->typ != 'c') && (cl->typ != 'm')))
						continue;
			}
			monitor_send_info(monitor_client_info('I', cl, sbuf), 0);
		}
	}
	monitor_send_info(NULL, 1);
}

static void monitor_send_details(char *txt, uint32_t tid){
	char buf[256];
	snprintf(buf, 255, "[D-----]%8X|%s\n", tid, txt);
	monitor_send_info(buf, 0);
}

static void monitor_send_details_version(){
	char buf[256];
	snprintf(buf, sizeof(buf), "[V-0000]version=%s, build=%s, system=%s-%s-%s\n", CS_VERSION_X, CS_SVN_VERSION,  CS_OS_CPU, CS_OS_HW, CS_OS_SYS);
	monitor_send_info(buf, 1);
}

static void monitor_send_keepalive_ack(){
	char buf[32];
	snprintf(buf, sizeof(buf), "[K-0000]keepalive_ack\n");
	monitor_send_info(buf, 1);
}

static void monitor_process_details_master(char *buf, uint32_t pid){
	snprintf(buf, 256, "Version=%s#%s", CS_VERSION_X, CS_SVN_VERSION);
	monitor_send_details(buf, pid);
	snprintf(buf, 256, "System=%s-%s-%s",  CS_OS_CPU, CS_OS_HW, CS_OS_SYS);
	monitor_send_details(buf, pid);
	snprintf(buf, 256, "DebugLevel=%d", cs_dblevel);
	monitor_send_details(buf, pid);
	snprintf(buf, 256, "MaxClients=UNLIMITED");
	monitor_send_details(buf, pid);
	snprintf(buf, 256, "ClientMaxIdle=%d sec", cfg.cmaxidle);
	monitor_send_details(buf, pid);
	if( cfg.max_log_size )
		snprintf(buf + 200, 56, "%d Kb", cfg.max_log_size);
	else
		cs_strncpy(buf + 200, "unlimited", 56);
	snprintf(buf, 256, "MaxLogsize=%s", buf + 200);
	monitor_send_details(buf, pid);
	snprintf(buf, 256, "ClientTimeout=%u ms", cfg.ctimeout);
	monitor_send_details(buf, pid);
	snprintf(buf, 256, "CacheDelay=%d ms", cfg.delay);
	monitor_send_details(buf, pid);
	if( cfg.cwlogdir ) {
                snprintf(buf, 256, "CwlogDir=%s", cfg.cwlogdir);
	        monitor_send_details(buf, pid);
        }
	if( cfg.preferlocalcards ) {
	        snprintf(buf, 256, "PreferlocalCards=%d", cfg.preferlocalcards);
	        monitor_send_details(buf, pid);
        }
	if( cfg.waitforcards ) {
	        snprintf(buf, 256, "WaitforCards=%d", cfg.waitforcards);
	        monitor_send_details(buf, pid);
        }
	snprintf(buf, 256, "LogFile=%s", cfg.logfile);
	monitor_send_details(buf, pid);
	if( cfg.mailfile ) {
	        snprintf(buf, 256, "MailFile=%s", cfg.mailfile);
	        monitor_send_details(buf, pid);
        }
	if( cfg.usrfile ) {
	        snprintf(buf, 256, "UsrFile=%s", cfg.usrfile);
	        monitor_send_details(buf, pid);
        }
	monitor_send_details(buf, pid);
	snprintf(buf, 256, "Sleep=%d", cfg.tosleep);
	monitor_send_details(buf, pid);
	snprintf(buf, 256, "Monitorport=%d", cfg.mon_port);
	monitor_send_details(buf, pid);
	snprintf(buf, 256, "Nice=%d", cfg.nice);
	monitor_send_details(buf, pid);
#ifdef WEBIF
	snprintf(buf, 256, "Restartmode=%d", cs_get_restartmode());
	monitor_send_details(buf, pid);
#else
	snprintf(buf, 256, "Restartmode=%s", "no");
	monitor_send_details(buf, pid);
#endif

	//  monitor_send_details(buf, pid);
}


static void monitor_process_details_reader(struct s_client *cl) {

	if (cfg.saveinithistory) {
		if (cl->reader->init_history) {
			char *ptr,*ptr1 = NULL;
			for (ptr=strtok_r(cl->reader->init_history, "\n", &ptr1); ptr; ptr=strtok_r(NULL, "\n", &ptr1)) {
				monitor_send_details(ptr, cl->tid);
				ptr1[-1]='\n';
			}
		}
	} else {
		monitor_send_details("Missing reader index or entitlement not saved!", cl->tid);
	}

}


static void monitor_process_details(char *arg){
	uint32_t tid = 0; //using threadid 8 positions hex see oscam-log.c //FIXME untested but pid isnt working anyway with threading
	struct s_client *cl = NULL, *cl1;
	char sbuf[256];

	if (!arg)
		cl = first_client; // no arg - show master
	else {
		if (sscanf(arg,"%X",&tid) == 1) {
			for (cl1=first_client; cl1 ; cl1=cl1->next)
				if (cl1->tid==tid)
					cl=cl1;
		}
	}

	if (!cl)
		monitor_send_details("Invalid TID", tid);
	else
	{
		//monitor_send_info(monitor_client_info('D', idx), 0); //FIXME
		switch(cl->typ)
		{
		case 's':
			monitor_process_details_master(sbuf, cl->tid);
			break;
		case 'c': case 'm':
			monitor_send_details(monitor_client_info(1, cl, sbuf), cl->tid);
			break;
		case 'r':
			monitor_process_details_reader(cl);//with client->typ='r' client->ridx is always filled and valid, so no need checking
			break;
		case 'p':
			monitor_send_details(monitor_client_info(1, cl, sbuf), cl->tid);
			break;
		}
	}
	monitor_send_info(NULL, 1);
}

static void monitor_send_login(void){
	char buf[64];
	struct s_client *cur_cl = cur_client();
	if (cur_cl->auth && cur_cl->account)
		snprintf(buf, sizeof(buf), "[A-0000]1|%s logged in\n", cur_cl->account->usr);
	else
		cs_strncpy(buf, "[A-0000]0|not logged in\n", sizeof(buf));
	monitor_send_info(buf, 1);
}

static void monitor_login(char *usr){
	char *pwd=NULL;
	int8_t res = 0;
	if ((usr) && (pwd=strchr(usr, ' ')))
		*pwd++=0;
	if (pwd)
		res = monitor_auth_client(trim(usr), trim(pwd));
	else
		res = monitor_auth_client(NULL, NULL);

	if (res == -1) {
		cs_disconnect_client(cur_client());
		return;
	}
	monitor_send_login();
}

static void monitor_logsend(char *flag){
	if (!flag) return; //no arg

	struct s_client *cur_cl = cur_client();
	if (strcmp(flag, "on")) {
		if (strcmp(flag, "onwohist")) {
			cur_cl->log=0;
			return;
		}
	}

	if (cur_cl->log)	// already on
		return;

	int32_t i, d = 0;
	if (!strcmp(flag, "on") && loghist){
		char *t_loghistptr = loghistptr, *ptr1 = NULL;
		if(loghistptr >= loghist + (cfg.loghistorysize) - 1)
			t_loghistptr = loghist;
		int32_t l1 = strlen(t_loghistptr+1) + 2;
		char *lastpos = loghist + (cfg.loghistorysize)-1;

		for (ptr1 = t_loghistptr + l1, i=0; i<200; i++, ptr1 = ptr1+l1) {
			l1 = strlen(ptr1)+1;
			if (!d && ((ptr1 >= lastpos) || (l1 < 2))) {
				ptr1 = loghist;
				l1 = strlen(ptr1)+1;
				d++;
			}

			if (d && ((ptr1 >= t_loghistptr) || (l1 < 2)))
				break;

			char p_usr[32], p_txt[512];
			size_t pos1 = strcspn(ptr1, "\t") + 1;

			cs_strncpy(p_usr, ptr1 , pos1 > sizeof(p_usr) ? sizeof(p_usr) : pos1);

			if ((p_usr[0]) && ((cur_cl->monlvl > 1) || (cur_cl->account && !strcmp(p_usr, cur_cl->account->usr)))) {
				snprintf(p_txt, sizeof(p_txt), "[LOG%03d]%s", cur_cl->logcounter, ptr1+pos1);
				cur_cl->logcounter=(cur_cl->logcounter + 1) % 1000;
				monitor_send(p_txt);
			}
		}
	}

	cur_cl->log=1;
}

static void monitor_set_debuglevel(char *flag){
	if (flag) {
		cs_dblevel = atoi(flag);
#ifndef WITH_DEBUG
		cs_log("*** Warning: Debug Support not compiled in ***");
#else
		cs_log("%s debug_level=%d", "all", cs_dblevel);
#endif
	}
}

static void monitor_get_account(){
	struct s_auth *account;
	char buf[256];
        int32_t count = 0;

	for (account=cfg.account; (account); account=account->next){
		count++;
		snprintf(buf, sizeof(buf), "[U-----]%s\n", account->usr);
		monitor_send_info(buf, 0);
	}
	snprintf(buf, sizeof(buf), "[U-----] %i User registered\n", count);
	monitor_send_info(buf, 1);
        return;
}

static void monitor_set_account(char *args){
	struct s_auth *account;
	char delimiter[] = " =";
	char *ptr, *saveptr1 = NULL;
	int32_t argidx, i, found;
	char *argarray[3];
	static const char *token[]={"au", "sleep", "uniq", "monlevel", "group", "services", "betatunnel", "ident", "caid", "chid", "class", "hostname", "expdate", "keepalive", "disabled"};
	int32_t tokencnt = sizeof(token)/sizeof(char *);
	char buf[256], tmp[64];

	argidx = 0;
	found = 0;

	snprintf(tmp, sizeof(tmp), "%s",args);
	snprintf(buf, sizeof(buf), "[S-0000]setuser: %s check\n", tmp);
	monitor_send_info(buf, 0);

	ptr = strtok_r(args, delimiter, &saveptr1);

	// resolve arguments
	while(ptr != NULL) {
		argarray[argidx]=trim(ptr);
		ptr = strtok_r(NULL, delimiter, &saveptr1);
		argidx++;
	}

	if(argidx != 3) {
		snprintf(buf, sizeof(buf), "[S-0000]setuser: %s failed - wrong number of parameters (%d)\n",tmp,  argidx);
		monitor_send_info(buf, 0);
		snprintf(buf, sizeof(buf), "[S-0000]setuser: %s end\n", tmp);
		monitor_send_info(buf, 1);
		return;
	}

	//search account
	for (account=cfg.account; (account) ; account=account->next){
		if (!strcmp(argarray[0], account->usr)){
			found = 1;
			break;
		}
	}

	if (found != 1){
		snprintf(buf, sizeof(buf), "[S-0000]setuser: %s failed - user %s not found\n",tmp , argarray[0]);
		monitor_send_info(buf, 0);
		snprintf(buf, sizeof(buf), "[S-0000]setuser: %s end\n", tmp);
		monitor_send_info(buf, 1);
		return;
	}

	found = -1;
	for (i = 0; i < tokencnt; i++){
		if (!strcmp(argarray[1], token[i])){
			// preparing the parameters before re-load
			switch(i) {

			case	6: clear_tuntab(&account->ttab); break;		//betatunnel

			case	8: clear_caidtab(&account->ctab); break;	//Caid
			}
			found = i;
		}
	}

	if (found < 0){
		snprintf(buf, sizeof(buf), "[S-0000]setuser: parameter %s not exist. possible values:\n", argarray[1]);
		monitor_send_info(buf, 0);
	        for (i = 0; i < tokencnt; i++){
		        snprintf(buf, sizeof(buf), "[S-0000]%s\n", token[i]);
		        monitor_send_info(buf, 0);
                }
		snprintf(buf, sizeof(buf),"[S-0000]setuser: %s end\n", tmp);
		monitor_send_info(buf, 1);
		return;
	} else {
		chk_account(token[found], argarray[2], account);
	}

	if (write_userdb(cfg.account)==0)
		cs_reinit_clients(cfg.account);

	snprintf(buf, sizeof(buf),"[S-0000]setuser: %s done - param %s set to %s\n", tmp, argarray[1], argarray[2]);
	monitor_send_info(buf, 1);
}

static void monitor_set_server(char *args){
	char delimiter[] = "=";
	char *ptr, *saveptr1;
	int32_t argidx, i, found;
	char *argarray[3];
	static const char *token[]={"clienttimeout", "fallbacktimeout", "clientmaxidle", "cachedelay", "bindwait", "netprio", "sleep", "unlockparental", "serialreadertimeout", "maxlogsize", "showecmdw", "waitforcards", "preferlocalcards"};
	char buf[256];

	argidx=0;	found=0;
	ptr = strtok_r(args, delimiter, &saveptr1);

	// resolve arguments
	while(ptr != NULL) {
		argarray[argidx]=trim(ptr);
		ptr = strtok_r(NULL, delimiter, &saveptr1);
		argidx++;
	}

	if(argidx != 2) {
		snprintf(buf, sizeof(buf),"[S-0000]setserver failed - wrong number of parameters (%d)\n", argidx);
		monitor_send_info(buf, 1);
		return;
	}

	trim(argarray[0]);
	trim(argarray[1]);
	strtolower(argarray[0]);

	for (i = 0; i < 13; i++)
		if (!strcmp(argarray[0], token[i]))	break;

	if (i < 13){
		chk_t_global(token[i],argarray[1]);
		snprintf(buf, sizeof(buf), "[S-0000]setserver done - param %s set to %s\n", argarray[0], argarray[1]);
		monitor_send_info(buf, 1);
	} else {
		snprintf(buf, sizeof(buf), "[S-0000]setserver failed - parameter %s not exist\n", argarray[0]);
		monitor_send_info(buf, 1);
		return;
	}

	if (cfg.ftimeout>=cfg.ctimeout) {
		cfg.ftimeout = cfg.ctimeout - 100;
		snprintf(buf, sizeof(buf), "[S-0000]setserver WARNING: fallbacktimeout adjusted to %u ms\n", cfg.ftimeout);
		monitor_send_info(buf, 1);
	}
	if(cfg.ftimeout < cfg.srtimeout) {
		cfg.ftimeout = cfg.srtimeout + 100;
		snprintf(buf, sizeof(buf), "[S-0000]setserver WARNING: fallbacktimeout adjusted to %u ms\n", cfg.ftimeout);
		monitor_send_info(buf, 1);
	}
	if(cfg.ctimeout < cfg.srtimeout) {
		cfg.ctimeout = cfg.srtimeout + 100;
		snprintf(buf, sizeof(buf), "[S-0000]setserver WARNING: clienttimeout adjusted to %u ms\n", cfg.ctimeout);
		monitor_send_info(buf, 1);
	}
	//kill(first_client->pid, SIGUSR1);
}

#ifdef WEBIF
static void monitor_restart_server(){
	cs_restart_oscam();
}
#endif

static void monitor_list_commands(const char *args[], int32_t cmdcnt){
	int32_t i;
	for (i = 0; i < cmdcnt; i++) {
		char buf[64];
		snprintf(buf, sizeof(buf), "[S-0000]commands: %s\n", args[i]);
		if(i < cmdcnt-1)
			monitor_send_info(buf, 0);
		else
			monitor_send_info(buf, 1);
	}
}

static int32_t monitor_process_request(char *req)
{
	int32_t i, rc;
	static const char *cmd[] = {"login",
								"exit",
								"log",
								"status",
								"shutdown",
								"reload",
								"details",
								"version",
								"debug",
								"getuser",
								"setuser",
								"setserver",
								"commands",
								"keepalive",
								"reread"
#ifdef WEBIF
								,"restart"
#endif
								};

	int32_t cmdcnt = sizeof(cmd)/sizeof(char *);  // Calculate the amount of items in array
	char *arg;
	struct s_client *cur_cl = cur_client();

	if( (arg = strchr(req, ' ')) ) { *arg++ = 0; trim(arg); }
	//trim(req);
	if ((!cur_cl->auth) && (strcmp(req, cmd[0])))	monitor_login(NULL);

	for (rc=1, i = 0; i < cmdcnt; i++)
		if (!strcmp(req, cmd[i])) {
			switch(i) {
			case  0:	monitor_login(arg); break;	// login
			case  1:	rc=0; break;	// exit
			case  2:	monitor_logsend(arg); break;	// log
			case  3:	monitor_process_info(); break;	// status
			case  4:	if (cur_cl->monlvl > 3) cs_exit_oscam(); break;	// shutdown
			case  5:	if (cur_cl->monlvl > 2) cs_accounts_chk(); break;	// reload
			case  6:	monitor_process_details(arg); break;	// details
			case  7:	monitor_send_details_version(); break;	// version
			case  8:	if (cur_cl->monlvl > 3) monitor_set_debuglevel(arg); break;	// debuglevel
			case  9:	if (cur_cl->monlvl > 3) monitor_get_account(); break;	// getuser
			case 10:	if (cur_cl->monlvl > 3) monitor_set_account(arg); break;	// setuser
			case 11:	if (cur_cl->monlvl > 3) monitor_set_server(arg); break;	// setserver
			case 12:	if (cur_cl->monlvl > 3) monitor_list_commands(cmd, cmdcnt); break;	// list commands
			case 13:	if (cur_cl->monlvl > 3) monitor_send_keepalive_ack(); break;	// keepalive
			case 14:	{ char buf[64];snprintf(buf, sizeof(buf), "[S-0000]reread\n");monitor_send_info(buf, 1); cs_card_info(); break; } // reread
#ifdef WEBIF
			case 15:	if (cur_cl->monlvl > 3) monitor_restart_server(); break;	// keepalive
#endif
			default:	continue;
			}
			break;
		}
	return(rc);
}

static void * monitor_server(struct s_client * client, uchar *mbuf, int32_t UNUSED(n)) {
	client->typ='m';
	monitor_process_request((char *)mbuf);
	
	return NULL;
}

void module_monitor(struct s_module *ph){
	static PTAB ptab; //since there is always only 1 monitor running, this is threadsafe
	ptab.ports[0].s_port = cfg.mon_port;
	ph->ptab = &ptab;
	ph->ptab->nports = 1;

	if (cfg.mon_aulow < 1)
		cfg.mon_aulow = 30;
	cs_strncpy(ph->desc, "monitor", sizeof(ph->desc));
	ph->type=MOD_CONN_UDP;
	ph->multi = 0;
	ph->s_ip = cfg.mon_srvip;
	ph->s_handler = monitor_server;
	ph->recv = monitor_recv;
	//  ph->send_dcw=NULL;
}


