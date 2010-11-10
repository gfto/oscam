#include "globals.h"
#ifdef CS_WITH_GBOX
#  include "csgbox/gbox.h"
#  define CS_VERSION_X  CS_VERSION "-gbx-" GBXVERSION
#else
#  define CS_VERSION_X  CS_VERSION
#endif


static void monitor_check_ip()
{
	int ok=0;
	struct s_ip *p_ip;

	if (cur_client()->auth) return;
	for (p_ip=cfg->mon_allowed; (p_ip) && (!ok); p_ip=p_ip->next)
		ok=((cur_client()->ip>=p_ip->ip[0]) && (cur_client()->ip<=p_ip->ip[1]));
	if (!ok)
	{
		cs_auth_client(cur_client(), (struct s_auth *)0, "invalid ip");
		cs_exit(0);
	}
}

static void monitor_auth_client(char *usr, char *pwd)
{
	struct s_auth *account;

	if (cur_client()->auth) return;
	if ((!usr) || (!pwd))
	{
		cs_auth_client(cur_client(), (struct s_auth *)0, NULL);
		cs_exit(0);
	}
	for (account=cfg->account, cur_client()->auth=0; (account) && (!cur_client()->auth);)
	{
		if (account->monlvl)
			cur_client()->auth=!(strcmp(usr, account->usr) | strcmp(pwd, account->pwd));
		if (!cur_client()->auth)
			account=account->next;
	}
	if (!cur_client()->auth)
	{
		cs_auth_client(cur_client(), (struct s_auth *)0, "invalid account");
		cs_exit(0);
	}
	if (cs_auth_client(cur_client(), account, NULL))
		cs_exit(0);
}

static int secmon_auth_client(uchar *ucrc)
{
	ulong crc;
	struct s_auth *account;

	if (cur_client()->auth)
	{
		int s=memcmp(cur_client()->ucrc, ucrc, 4);
		if (s)
			cs_log("wrong user-crc or garbage !?");
		return(!s);
	}
	cur_client()->crypted=1;
	crc=(ucrc[0]<<24) | (ucrc[1]<<16) | (ucrc[2]<<8) | ucrc[3];
	for (account=cfg->account; (account) && (!cur_client()->auth); account=account->next)
		if ((account->monlvl) &&
				(crc==crc32(0L, MD5((unsigned char *)account->usr, strlen(account->usr), cur_client()->dump), 16)))
		{
			memcpy(cur_client()->ucrc, ucrc, 4);
			aes_set_key((char *)MD5((unsigned char *)account->pwd, strlen(account->pwd), cur_client()->dump));
			if (cs_auth_client(cur_client(), account, NULL))
				cs_exit(0);
			cur_client()->auth=1;
		}
	if (!cur_client()->auth)
	{
		cs_auth_client(cur_client(), (struct s_auth *)0, "invalid user");
		cs_exit(0);
	}
	return(cur_client()->auth);
}

int monitor_send_idx(struct s_client *cl, char *txt)
{
	int l;
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
	strcpy((char *)buf+10, txt);
	memcpy(buf+5, i2b(4, crc32(0L, buf+10, l-10)), 4);
	aes_encrypt_idx(cl, buf+5, l-5);
	return(sendto(cl->udp_fd, buf, l, 0,
			(struct sockaddr *)&cl->udp_sa,
			sizeof(cl->udp_sa)));
}

#define monitor_send(t) monitor_send_idx(cur_client(), t)

static int monitor_recv(struct s_client * client, uchar *buf, int l)
{
	int n;
	uchar nbuf[3] = { 'U', 0, 0 };
	static int bpos=0;
	static uchar *bbuf=NULL;
	if (!bbuf)
	{
		bbuf=(uchar *)malloc(l);
		if (!bbuf)
		{
			cs_log("Cannot allocate memory (errno=%d)", errno);
			cs_exit(1);
		}
	}
	if (bpos)
		memcpy(buf, bbuf, n=bpos);
	else
		n=recv_from_udpipe(buf);
	bpos=0;
	if (!n) return(buf[0]=0);
	if (buf[0]=='&')
	{
		int bsize;
		if (n<21)	// 5+16 is minimum
		{
			cs_log("packet to short !");
			return(buf[0]=0);
		}
		if (!secmon_auth_client(buf+1))
			return(buf[0]=0);
		aes_decrypt(buf+5, 16);
		bsize=boundary(4, buf[9]+5)+5;
		// cs_log("n=%d bsize=%d", n, bsize);
		if (n>bsize)
		{
			// cs_log("DO >>>> copy-back");
			memcpy(bbuf, buf+bsize, bpos=n-bsize);
			n=bsize;
			write_to_pipe(client->fd_m2c, PIP_ID_UDP, (uchar*)&nbuf, sizeof(nbuf));
		}
		else if (n<bsize)
		{
			cs_log("packet-size mismatch !");
			return(buf[0]=0);
		}
		aes_decrypt(buf+21, n-21);
		if (memcmp(buf+5, i2b(4, crc32(0L, buf+10, n-10)), 4))
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
		monitor_check_ip();
		buf[n]='\0';
		if ((p=(uchar *)strchr((char *)buf, 10)) && (bpos=n-(p-buf)-1))
		{
			memcpy(bbuf, p+1, bpos);
			n=p-buf;
			write_to_pipe(client->fd_m2c, PIP_ID_UDP, (uchar*)&nbuf, sizeof(nbuf));
		}
	}
	buf[n]='\0';
	n=strlen(trim((char *)buf));
	if (n) client->last=time((time_t *) 0);
	return(n);
}

static void monitor_send_info(char *txt, int last)
{
	static int seq=0, counter=0;
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
		sprintf(buf, "%03d", counter);
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

static char *monitor_client_info(char id, struct s_client *cl){
	static char sbuf[256];
	sbuf[0] = '\0';

	if (cl){
		char ldate[16], ltime[16], *usr;
		int lsec, isec, con, cau, lrt;
		time_t now;
		struct tm *lt;
		now=time((time_t)0);

		if	((cfg->mon_hideclient_to <= 0) ||
				(now-cl->lastecm < cfg->mon_hideclient_to) ||
				(now-cl->lastemm < cfg->mon_hideclient_to) ||
				(cl->typ != 'c'))
		{
			lsec=now-cl->login;
			isec=now-cl->last;
			usr=cl->usr;
			if (((cl->typ == 'r') || (cl->typ == 'p')) && (con=get_ridx(cl->reader)) >= 0)
				usr=cl->reader->label;
			if (cl->dup)
				con=2;
			else
				if ((cl->tosleep) && (now-cl->lastswitch>cl->tosleep))
					con = 1;
				else
					con = 0;
			
			if( (cau = get_ridx(cl->aureader) + 1) )
				if ((now-cl->lastemm) /60 > cfg->mon_aulow)
					cau=-cau;
			if( cl->typ == 'r')
			{
			    lrt = get_ridx(cl->reader);
			    if( lrt >= 0 )
                    lrt = 10 + cl->reader->card_status;
			}
			else
                lrt = cl->cwlastresptime;
			lt = localtime(&cl->login);
			sprintf(ldate, "%02d.%02d.%02d", lt->tm_mday, lt->tm_mon+1, lt->tm_year % 100);
			int cnr=get_threadnum(cl);
			sprintf(ltime, "%02d:%02d:%02d", lt->tm_hour, lt->tm_min, lt->tm_sec);
                        sprintf(sbuf, "[%c--CCC]%8lX|%c|%d|%s|%d|%d|%s|%d|%s|%s|%s|%d|%04X:%04X|%s|%d|%d|%d|%d|%d|%d|%d|%d|%d|%d\n",
					id, (unsigned long)cl->thread, cl->typ, cnr, usr, cau, cl->crypted,
					cs_inet_ntoa(cl->ip), cl->port, monitor_get_proto(cl),
					ldate, ltime, lsec, cl->last_caid, cl->last_srvid,
					get_servicename(cl->last_srvid, cl->last_caid), isec, con,
                                        cl->cwfound, cl->cwnot, cl->cwcache, cl->cwignored,
                                        cl->cwtout, cl->emmok, cl->emmnok, lrt);
		}
	}
	return(sbuf);
}

static void monitor_process_info(){
	time_t now = time((time_t)0);

	struct s_client *cl;
	for (cl=first_client; cl ; cl=cl->next) {
		if	((cfg->mon_hideclient_to <= 0) ||
				( now-cl->lastecm < cfg->mon_hideclient_to) ||
				( now-cl->lastemm < cfg->mon_hideclient_to) ||
				( cl->typ != 'c')){
			if ((cur_client()->monlvl < 2) && (cl->typ != 's')) {
					if 	((strcmp(cur_client()->usr, cl->usr)) ||
							((cl->typ != 'c') && (cl->typ != 'm')))
						continue;
			}
			monitor_send_info(monitor_client_info('I', cl), 0);
		}
	}
	monitor_send_info(NULL, 1);
}

static void monitor_send_details(char *txt, unsigned int tid){
	char buf[256];
	snprintf(buf, 255, "[D-----]%8X|%s\n", tid, txt);
	monitor_send_info(buf, 0);
}

static void monitor_send_details_version(){
	char buf[256];
	sprintf(buf, "[V-0000]version=%s, build=%s, system=%s-%s-%s\n", CS_VERSION_X, CS_SVN_VERSION,  CS_OS_CPU, CS_OS_HW, CS_OS_SYS);
	monitor_send_info(buf, 1);
}

static void monitor_send_keepalive_ack(){
	char buf[32];
	sprintf(buf, "[K-0000]keepalive_ack\n");
	monitor_send_info(buf, 1);
}

static void monitor_process_details_master(char *buf, unsigned long pid){
	sprintf(buf, "Version=%s#%s", CS_VERSION_X, CS_SVN_VERSION);
	monitor_send_details(buf, pid);
	sprintf(buf, "System=%s-%s-%s",  CS_OS_CPU, CS_OS_HW, CS_OS_SYS);
	monitor_send_details(buf, pid);
	sprintf(buf, "DebugLevel=%d", cfg->debuglvl);
	monitor_send_details(buf, pid);
	sprintf(buf, "MaxClients=UNLIMITED");
	monitor_send_details(buf, pid);
	sprintf(buf, "ClientMaxIdle=%ld sec", cfg->cmaxidle);
	monitor_send_details(buf, pid);
	if( cfg->max_log_size )
		sprintf(buf + 200, "%d Kb", cfg->max_log_size);
	else
		strcpy(buf + 200, "unlimited");
	sprintf(buf, "MaxLogsize=%s", buf + 200);
	monitor_send_details(buf, pid);
	sprintf(buf, "ClientTimeout=%lu ms", cfg->ctimeout);
	monitor_send_details(buf, pid);
	sprintf(buf, "CacheDelay=%ld ms", cfg->delay);
	monitor_send_details(buf, pid);
	if( cfg->cwlogdir ) {
                sprintf(buf, "CwlogDir=%s", cfg->cwlogdir);
	        monitor_send_details(buf, pid);
        }
	if( cfg->preferlocalcards ) {
	        sprintf(buf, "PreferlocalCards=%d", cfg->preferlocalcards);
	        monitor_send_details(buf, pid);
        }
	if( cfg->waitforcards ) {
	        sprintf(buf, "WaitforCards=%d", cfg->waitforcards);
	        monitor_send_details(buf, pid);
        }
	sprintf(buf, "LogFile=%s", cfg->logfile);
	monitor_send_details(buf, pid);
	if( cfg->usrfile ) {
	        sprintf(buf, "UsrFile=%s", cfg->usrfile);
	        monitor_send_details(buf, pid);
        }
	sprintf(buf, "ResolveDelay=%d", cfg->resolvedelay);
	monitor_send_details(buf, pid);
	sprintf(buf, "Sleep=%d", cfg->tosleep);
	monitor_send_details(buf, pid);
	sprintf(buf, "Monitorport=%d", cfg->mon_port);
	monitor_send_details(buf, pid);
	sprintf(buf, "Nice=%d", cfg->nice);
	monitor_send_details(buf, pid);

	//  monitor_send_details(buf, pid);
}


static void monitor_process_details_reader(struct s_client *cl) {

	if (cfg->saveinithistory) {
		FILE *fp;
		char filename[32];
		char buffer[128];
		sprintf(filename, "%s/reader%d", get_tmp_dir(), get_ridx(cl->reader));
		fp = fopen(filename, "r");

		if (fp) {
			while(fgets(buffer, 128, fp) != NULL) {
				monitor_send_details(buffer, (unsigned long)(cl->thread));
			}
			fclose(fp);
		}
	} else {
		monitor_send_details("Missing reader index or entitlement not saved!", (unsigned long)(cl->thread));
	}

}


static void monitor_process_details(char *arg){
	unsigned long tid = 0; //using threadid 8 positions hex see oscam-log.c //FIXME untested but pid isnt working anyway with threading
	struct s_client *cl;
	char sbuf[256];

	if (!arg)
		cl = first_client; // no arg - show master
	else
		if (sscanf(arg,"%lX",&tid) == 1)
			cl = get_client_by_tid(tid);
		else
			cl = NULL;

	if (!cl)
		monitor_send_details("Invalid TID", tid);
	else
	{
		//monitor_send_info(monitor_client_info('D', idx), 0); //FIXME
		switch(cl->typ)
		{
		case 's':
			monitor_process_details_master(sbuf, (unsigned long)(cl->thread));
			break;
		case 'c': case 'm':
			monitor_send_details(monitor_client_info(1, cl), (unsigned long)(cl->thread));
			break;
		case 'r':
			monitor_process_details_reader(cl);//with client->typ='r' client->ridx is always filled and valid, so no need checking
			break;
		case 'p':
			monitor_send_details(monitor_client_info(1, cl), (unsigned long)(cl->thread));
			break;
		}
	}
	monitor_send_info(NULL, 1);
}

static void monitor_send_login(void){
	char buf[64];
	if (cur_client()->auth)
		sprintf(buf, "[A-0000]1|%s logged in\n", cur_client()->usr);
	else
		strcpy(buf, "[A-0000]0|not logged in\n");
	monitor_send_info(buf, 1);
}

static void monitor_login(char *usr){
	char *pwd=NULL;
	if ((usr) && (pwd=strchr(usr, ' ')))
		*pwd++=0;
	if (pwd)
		monitor_auth_client(trim(usr), trim(pwd));
	else
		monitor_auth_client(NULL, NULL);
	monitor_send_login();
}

static void monitor_logsend(char *flag){
#ifdef CS_LOGHISTORY
	int i;
#endif
	if (!flag) return; //no arg

	if (strcmp(flag, "on")) {
		if (strcmp(flag, "onwohist")) {
			cur_client()->log=0;
			return;
		}
	}

	if (cur_client()->log)	// already on
		return;
#ifdef CS_LOGHISTORY
	if (!strcmp(flag, "on")){
		for (i = (loghistidx + 3) % CS_MAXLOGHIST; i != loghistidx; i = (i + 1) % CS_MAXLOGHIST){
			char *p_usr, *p_txt;
			p_usr=(char *)(loghist+(i*CS_LOGHISTSIZE));
			p_txt = p_usr + 32;
			if ((p_txt[0]) && ((cur_client()->monlvl > 1) || (!strcmp(p_usr, cur_client()->usr)))) {
				char sbuf[8];
				sprintf(sbuf, "%03d", cur_client()->logcounter);
				cur_client()->logcounter=(cur_client()->logcounter + 1) % 1000;
				memcpy(p_txt + 4, sbuf, 3);
				monitor_send(p_txt);
			}
		}
	}
#endif
	cur_client()->log=1;
}

static void monitor_set_debuglevel(char *flag){
	cfg->debuglvl = atoi(flag);
	cs_debug_level();
}

static void monitor_get_account(){
	struct s_auth *account;
	char buf[256];
        int count = 0;

	for (account=cfg->account; (account); account=account->next){
                count++;
		snprintf(buf, 255, "[U-----]%s\n", account->usr);
	        monitor_send_info(buf, 0);
	}
	sprintf(buf, "[U-----] %i User registered\n", count);
	monitor_send_info(buf, 1);
        return;
}

static void monitor_set_account(char *args){
	struct s_auth *account;
	char delimiter[] = " =";
	char *ptr;
	int argidx, i, found;
	char *argarray[3];
	static const char *token[]={"au", "sleep", "uniq", "monlevel", "group", "services", "betatunnel", "ident", "caid", "chid", "class", "hostname", "expdate", "keepalive", "disabled"};
	int tokencnt = sizeof(token)/sizeof(char *);
	char buf[256], tmp[64];

	argidx = 0;
	found = 0;

	sprintf(tmp, "%s",args);
	sprintf(buf, "[S-0000]setuser: %s check\n", tmp);
	monitor_send_info(buf, 0);

	ptr = strtok(args, delimiter);

	// resolve arguments
	while(ptr != NULL) {
		argarray[argidx]=trim(ptr);
		ptr = strtok(NULL, delimiter);
		argidx++;
	}

	if(argidx != 3) {
		sprintf(buf, "[S-0000]setuser: %s failed - wrong number of parameters (%d)\n",tmp,  argidx);
		monitor_send_info(buf, 0);
		sprintf(buf, "[S-0000]setuser: %s end\n", tmp);
		monitor_send_info(buf, 1);
		return;
	}

	//search account
	for (account=cfg->account; (account) ; account=account->next){
		if (!strcmp(argarray[0], account->usr)){
			found = 1;
			break;
		}
	}

	if (found != 1){
		sprintf(buf, "[S-0000]setuser: %s failed - user %s not found\n",tmp , argarray[0]);
		monitor_send_info(buf, 0);
		sprintf(buf, "[S-0000]setuser: %s end\n", tmp);
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
		sprintf(buf, "[S-0000]setuser: parameter %s not exist. possible values:\n", argarray[1]);
		monitor_send_info(buf, 0);
	        for (i = 0; i < tokencnt; i++){
		        sprintf(buf, "[S-0000]%s\n", token[i]);
		        monitor_send_info(buf, 0);
                }
		sprintf(buf, "[S-0000]setuser: %s end\n", tmp);
		monitor_send_info(buf, 1);
		return;
	} else {
		chk_account(token[found], argarray[2], account);
	}

	if (write_userdb(cfg->account)==0)
		cs_reinit_clients();

	sprintf(buf, "[S-0000]setuser: %s done - param %s set to %s\n", tmp, argarray[1], argarray[2]);
	monitor_send_info(buf, 1);
}

static void monitor_set_server(char *args){
	char delimiter[] = "=";
	char *ptr;
	int argidx, i, found;
	char *argarray[3];
	static const char *token[]={"clienttimeout", "fallbacktimeout", "clientmaxidle", "cachedelay", "bindwait", "netprio", "resolvedelay", "sleep", "unlockparental", "serialreadertimeout", "maxlogsize", "showecmdw", "waitforcards", "preferlocalcards"};
	char buf[256];

	argidx=0;	found=0;
	ptr = strtok(args, delimiter);

	// resolve arguments
	while(ptr != NULL) {
		argarray[argidx]=trim(ptr);
		ptr = strtok(NULL, delimiter);
		argidx++;
	}

	if(argidx != 2) {
		sprintf(buf, "[S-0000]setserver failed - wrong number of parameters (%d)\n", argidx);
		monitor_send_info(buf, 1);
		return;
	}

	trim(argarray[0]);
	trim(argarray[1]);
	strtolower(argarray[0]);

	for (i = 0; i < 14; i++)
		if (!strcmp(argarray[0], token[i]))	break;

	if (i < 14){
		chk_t_global(token[i],argarray[1]);
		sprintf(buf, "[S-0000]setserver done - param %s set to %s\n", argarray[0], argarray[1]);
		monitor_send_info(buf, 1);
	} else {
		sprintf(buf, "[S-0000]setserver failed - parameter %s not exist\n", argarray[0]);
		monitor_send_info(buf, 1);
		return;
	}

	if (cfg->ftimeout>=cfg->ctimeout) {
		cfg->ftimeout = cfg->ctimeout - 100;
		sprintf(buf, "[S-0000]setserver WARNING: fallbacktimeout adjusted to %lu ms\n", cfg->ftimeout);
		monitor_send_info(buf, 1);
	}
	if(cfg->ftimeout < cfg->srtimeout) {
		cfg->ftimeout = cfg->srtimeout + 100;
		sprintf(buf, "[S-0000]setserver WARNING: fallbacktimeout adjusted to %lu ms\n", cfg->ftimeout);
		monitor_send_info(buf, 1);
	}
	if(cfg->ctimeout < cfg->srtimeout) {
		cfg->ctimeout = cfg->srtimeout + 100;
		sprintf(buf, "[S-0000]setserver WARNING: clienttimeout adjusted to %lu ms\n", cfg->ctimeout);
		monitor_send_info(buf, 1);
	}
	//kill(first_client->pid, SIGUSR1);
}

static void monitor_list_commands(const char *args[], int cmdcnt){
	int i;
	for (i = 0; i < cmdcnt; i++) {
		char buf[64];
		sprintf(buf, "[S-0000]commands: %s\n", args[i]);
		if(i < cmdcnt-1)
			monitor_send_info(buf, 0);
		else
			monitor_send_info(buf, 1);
	}
}

static int monitor_process_request(char *req)
{
	int i, rc;
	static const char *cmd[] = {"login", "exit", "log", "status", "shutdown", "reload", "details", "version", "debug", "getuser", "setuser", "setserver", "commands", "keepalive", "reread"};
	int cmdcnt = sizeof(cmd)/sizeof(char *);  // Calculate the amount of items in array
	char *arg;

	if( (arg = strchr(req, ' ')) ) { *arg++ = 0; trim(arg); }
	//trim(req);
	if ((!cur_client()->auth) && (strcmp(req, cmd[0])))	monitor_login(NULL);

	for (rc=1, i = 0; i < cmdcnt; i++)
		if (!strcmp(req, cmd[i])) {
			switch(i) {
			case  0:	monitor_login(arg); break;	// login
			case  1:	rc=0; break;	// exit
			case  2:	monitor_logsend(arg); break;	// log
			case  3:	monitor_process_info(); break;	// status
			case  4:	if (cur_client()->monlvl > 3) cs_exit(SIGQUIT); break;	// shutdown
			case  5:	if (cur_client()->monlvl > 2) cs_reinit_clients(); break;	// reload
			case  6:	monitor_process_details(arg); break;	// details
			case  7:	monitor_send_details_version(); break;	// version
			case  8:	if (cur_client()->monlvl > 3) monitor_set_debuglevel(arg); break;	// debuglevel
			case  9:	if (cur_client()->monlvl > 3) monitor_get_account(); break;	// getuser
			case 10:	if (cur_client()->monlvl > 3) monitor_set_account(arg); break;	// setuser
			case 11:	if (cur_client()->monlvl > 3) monitor_set_server(arg); break;	// setserver
			case 12:	if (cur_client()->monlvl > 3) monitor_list_commands(cmd, cmdcnt); break;	// list commands
			case 13:	if (cur_client()->monlvl > 3) monitor_send_keepalive_ack(); break;	// keepalive
			case 14:	{ char buf[64];sprintf(buf, "[S-0000]reread\n");monitor_send_info(buf, 1); cs_card_info(); break; } // reread
			default:	continue;
			}
			break;
		}
	return(rc);
}

static void * monitor_server(void *cli){
	int n;
	uchar mbuf[1024];

	struct s_client * client = (struct s_client *) cli;
	client->thread=pthread_self();
	pthread_setspecific(getclient, cli);
	client->typ='m';
	while (((n = process_input(mbuf, sizeof(mbuf), cfg->cmaxidle)) >= 0) && monitor_process_request((char *)mbuf));
	cs_disconnect_client(cli);
	return NULL;
}

void module_monitor(struct s_module *ph){
	static PTAB ptab; //since there is always only 1 monitor running, this is threadsafe
	ptab.ports[0].s_port = cfg->mon_port;
	ph->ptab = &ptab;
	ph->ptab->nports = 1;

	if (cfg->mon_aulow < 1)
		cfg->mon_aulow = 30;
	strcpy(ph->desc, "monitor");
	ph->type=MOD_CONN_UDP;
	ph->multi = 0;
	ph->watchdog = 1;
	ph->s_ip = cfg->mon_srvip;
	ph->s_handler = monitor_server;
	ph->recv = monitor_recv;
	//  ph->send_dcw=NULL;
}


