#include <u.h>
#include <libc.h>
#include <ctype.h>

/* hubshell is the client for hubfs, usually started by the hub wrapper script */
/* it handles attaching and detaching from hub-connected rcs and creating new ones */

enum {
	SMBUF = 512,
};

void
warn(char *fmt, ...)
{
	va_list arg;
	char buf[SMBUF*2];	/* somewhat arbitrary */
	int n;

	if((n = snprint(buf, sizeof(buf), "%s: ", argv0)) < 0)
		abort();
	va_start(arg, fmt);
	vseprint(buf+n, buf+sizeof(buf), fmt, arg);
	va_end(arg);

	fprint(2, "%s\n", buf);
}

enum{
	Detach,
	Remote,
	Local,
	Attach,
	Err,
	In,
	Out,
	Fortun,
	Unfort,
	Echoes,
	Unecho,
	Eof,
	Freeze,
	Melt,
	Fear,
	Calm,
	Trunc,
	Notrunc,
	List,
	Status,
	Quit,
	NCmd,
};

char *cmdstr[] = {
	[Detach] = "detach",
	[Remote] = "remote",
	[Local] = "local",
	[Attach] = "attach",
	[Err] = "err",
	[In] = "in",
	[Out] = "out",
	[Fortun] = "fortun",
	[Unfort] = "unfort",
	[Echoes] = "echoes",
	[Unecho] = "unecho",
	[Eof] = "eof",
	[Freeze] = "freeze",
	[Melt] = "melt",
	[Fear] = "fear",
	[Calm] = "calm",
	[Trunc] = "trunc",
	[Notrunc] = "notrunc",
	[List] = "list",
	[Status] = "status",
	[Quit] = "quit",
	[NCmd] = nil,
};


int
getcmd(char *s)
{
	int i;

	for(i=0; i<NCmd; i++){
		if(strncmp(cmdstr[i], s, strlen(cmdstr[i])) == 0)
			break;
	}

	return i;
}

typedef struct Shell Shell;

/* A Shell opens fds of 3 hubfiles and bucket-brigades data between the hubfs and std i/o fds*/
struct Shell {
	int fd[3];
	long fddelay[3];
	char basename[SMBUF];
	char *fdname[3];
	char shellctl;
	QLock;
	int ref;
};

Shell *activeshell;
int cpid;
int notereceived;

/* string storage for names of hubs and paths */
char shellname[SMBUF];
char mtpt[SMBUF];
char srvname[SMBUF];
char ctlname[SMBUF];
char basehub[SMBUF];
char *prompt = "io; ";
int promptlen;

/* flags for rc commands to run when flushing buffers */
int fortunate;
int echoes;

Shell* setupshell(char*);
void startshell(Shell*);
void fdread(int, Shell*);
void fdinput(int, Shell*);
int touch(char*);
void freeshell(Shell*);
int parsebuf(Shell*, char*, int);
void killfamily(void);

void*
emalloc(ulong sz)
{
	void *v;

	if((v = malloc(sz)) == nil)
		sysfatal("emalloc: %r");
	memset(v, 0, sz);

	setmalloctag(v, getcallerpc(&sz));
	return v;
}

int
erfork(int flags)
{
	int n;
	if((n = rfork(flags)) < 0)
		sysfatal("erfork: %r");
	return n;
}

/* set shellgroup variables and open file descriptors */
Shell*
setupshell(char *name)
{
	Shell *s;
	int i;

	s = emalloc(sizeof(*s));
	for(i=0; i<3; i++)
		s->fd[i] = -1;
	snprint(s->basename, sizeof(s->basename), "%s/%s", mtpt, name);
	for(i = 1; i < 3; i++){
		if((s->fdname[i] = smprint("%s%d", s->basename, i)) == nil)
			sysfatal("smprint: %r");
		if((s->fd[i] = open(s->fdname[i], OREAD)) < 0){
		err:
			warn("giving up on task - can't open %s: %r", s->fdname[i]);
			freeshell(s);
			return nil;
		};
	}
	s->fddelay[0] = -1;
	s->fddelay[1] = -1;
	s->fddelay[2] = -1;
	if((s->fdname[0] = smprint("%s%d", s->basename, 0)) == nil)
		sysfatal("smprint: %r");
	if((s->fd[0] = open(s->fdname[0], OWRITE)) < 0){
		i = 0;
		goto err;
	}
	strncpy(basehub, s->fdname[0] + strlen(mtpt)+1, sizeof(basehub));
	return s;
}

void
freeactiveshell(void)
{
	freeshell(activeshell);
}

void
startshell(Shell *s)
{
	if(cpid != -1)
		killfamily();

	activeshell = s;

	if(cpid = erfork(RFPROC|RFMEM|RFNOTEG|RFNOWAIT)){
		atexit(freeactiveshell);
		fdinput(0, s);
	} else if(erfork(RFPROC|RFMEM|RFNOWAIT)){
		atexit(freeactiveshell);
		fdread(1, s);
	} else{
		atexit(freeactiveshell);
		fdread(2, s);
	}

	exits(nil);
}

void
fdread(int fd, Shell *s)
{
	char buf[8192+1];
	long n;

	s->ref++;
	while((n=read(s->fd[fd], buf, sizeof(buf)-1)) > 0){
		buf[n] = '\0';
		if(s->fddelay[fd] >= 0)
			sleep(s->fddelay[fd]);
		if(write(fd, buf, n) != n){
			warn("error writing to %s on fd[%d]: %r", s->fdname[fd], s->fd[fd]);
			return;
		}
		if(s->shellctl == 'q')
			return;
	}
	if(n < 0)
		warn("error reading from %s on fd[%d]: %r", s->fdname[fd], s->fd[fd]);
}

/* write user input to hubfile */
void
fdinput(int fd, Shell *s)
{
	char buf[8192+1];
	long n;
	char ctlbuf[8192];
	int ctlfd;

	s->ref++;
readloop:
	while((n=read(fd, buf, sizeof(buf)-1))>0){
		buf[n] = '\0';
		/* check for user %command */
		if(buf[0] == '%' && parsebuf(s, buf+1, s->fd[fd]))
			continue;
		if(s->fddelay[fd] >= 0)
			sleep(s->fddelay[fd]);
		if(write(s->fd[fd], buf, n)!=n)
			warn("error writing to %s on fd[%d]: %r", s->fdname[fd], s->fd[fd]);
		if(s->shellctl == 'q')
			return;
	}
	/* eof input from user, send message to hubfs ctl file */
	if(n == 0){
		if((ctlfd = open(ctlname, OWRITE)) < 0){
			warn("can't open ctl file: %r");
			goto readloop;
		}
		snprint(ctlbuf, sizeof(ctlbuf), "eof %s\n", basehub);
		n = strlen(ctlbuf);
		if(write(ctlfd, ctlbuf, n) != n)
			warn("error writing to %s on fd[%d]: %r", ctlname, ctlfd);
		close(ctlfd);
	}
	/* hack to fix infinite loop bug with headless drawterm */
	if(n < 0 && notereceived == 0)
		return;
	notereceived = 0;
	goto readloop;		/* Use more gotos, they aren't harmful */
}

/* for creating new hubfiles */
int
touch(char *name)
{
	int fd;

	if((fd = create(name, OREAD|OEXCL, 0660)) < 0){
		warn("%s: cannot create: %r", name);
		return 1;
	}
	close(fd);
	return 0;
}

/* close fds when a shell moves to new hubfs */
void
freeshell(Shell *s)
{
	int i;

	if(--s->ref > 0 || !canqlock(s))
		return;
	for(i = 0; i < 3; i++){
		if(s->fd[i] >= 0)
			close(s->fd[i]);
		if(s->fdname[i] != nil)
			free(s->fdname[i]);
	}
	free(s);
}

void
endshell(Shell *s, Shell *ns, int fd)
{
	s->shellctl = 'q';
	if(fortunate) write(fd, "fortune\n", 8);
	if(echoes) write(fd, "echo\n", 5);

	/* races everywhere */
	sleep(100);
	killfamily();
	freeshell(s);
	sleep(100);
	if(ns)
		startshell(ns);
}

/* handles %commands */
int
parsebuf(Shell *s, char *buf, int ofd)
{
	char *p, *q;
	Shell *newshell;
	char ctlbuf[SMBUF];
	int ctlfd;
	int cmd, cmdlen;
	long n;

	cmd = getcmd(buf);

	if(cmd != NCmd){
		if(p = strchr(buf, '\n'))
			*p = '\0';
		cmdlen = strlen(cmdstr[cmd]);
		if(buf[cmdlen] != '\0'){
			p = buf+cmdlen;
			while(*p == ' ' || *p == '\t')
				p++;
			if(*p == '\0')
				p = nil;
		}
		else
			p = nil;
	} else
		p = nil;

	switch(cmd){
	case Detach:	/* %detach closes hubshell fds and exits */
		warn("detaching");
		endshell(s, nil, ofd);
		exits(nil);
	case Remote:	/* %remote command makes new shell on hubfs host by sending hub -b command */
		if(p == nil){
			warn("remote needs a name parameter to create new hubs");
			break;
		}
		warn("attaching to remote %s, new shell %s", srvname, p);
		fprint(ofd, "hub -b %s %s\n", srvname, p);
		sleep(100);
		newshell = setupshell(p);
		if(newshell == nil){
			warn("failed to setup up client shell, maybe problems on remote end");
			break;
		}
		endshell(s, newshell, ofd);
	case Local:	/* %local command makes new shell on local machine by executing the hub command and exiting */
		if(p == nil){
			warn("local needs a name parameter to create new hubs");
			break;
		}
		warn("attaching to %s, new shell %s", srvname, p);
		endshell(s, nil, ofd);
		execl("/bin/hub", "hub", srvname, p, 0);
		sysfatal("execl: %r");
	case Attach:	/* %attach name starts new shell and exits the current one */
		if(p == nil){
			warn("attach needs a name parameter to know what hubs to use, try %%list");
			break;
		}
		warn("attaching to %s, shell %s", srvname, p);
		newshell = setupshell(p);
		if(newshell == nil){
			warn("client setupshell() failed - do you need to create it with remote NAME?");
			break;
		}
		endshell(s, newshell, ofd);
	case Err:	/* %err %in %out LONG set the delay before reading/writing on that fd to LONG milliseconds */
	case In:
	case Out:
		if(p != nil)
			n = strtol(p, &q, 10);
		else
			n = 0; /* shut up compiler */
		if(p == nil || p == q || *q != '\0'){
			warn("%s hub delay setting requires numeric delay", cmdstr[cmd]);
			break;
		}
		s->fddelay[cmd-Err] = n;
		warn("%s hub delay set to %ld", cmdstr[cmd], n);
		break;
	case Fortun:	/* %fortun and %echoes turn on buffer flush commands %unfort and %unecho deactivate */
		warn("fortunes active");
		fortunate = 1;
		break;
	case Unfort:
		warn("fortunes deactivated");
		fortunate = 0;
		break;
	case Echoes:
		warn("echoes active");
		echoes = 1;
		break;
	case Unecho:
		warn("echoes deactivated");
		echoes = 0;
		break;
	case Eof:	/* send eof or freeze/melt/fear/calm/trunc/notrunc messages to ctl file */
	case Freeze:
	case Melt:
	case Fear:
	case Calm:
	case Trunc:
	case Notrunc:
		if((ctlfd = open(ctlname, OWRITE)) < 0){
			warn("can't open ctl file");
			break;
		}
		n = snprint(ctlbuf, sizeof(ctlbuf), "%s %s\n", cmdstr[cmd], basehub);
		if(write(ctlfd, ctlbuf, n) != n)
			warn("error writing to %s on fd[%d]: %r", ctlname, ctlfd);
		close(ctlfd);
		break;
	case List:	/* %list displays attached hubs %status reports variable settings */
		warn("listing mounted hubfs at %s", mtpt);
		if((n = rfork(RFPROC|RFNOTEG|RFNOWAIT)) == 0){
			execl("/bin/lc", "lc", mtpt, 0);
			sysfatal("execl: %r");
		} else if(n < 0)
			warn("rfork: %r");
		break;
	case Status:
		fprint(2, "\t%s status: attached to mounted %s of /srv/%s\n"
			"\tfd[0] delay: %ld  fd[1] delay: %ld  fd[2] delay: %ld\n"
			, argv0, s->basename, srvname, s->fddelay[0], s->fddelay[1], s->fddelay[2]);
		if(fortunate) fprint(2, "\tfortune fd flush active\n");
		if(echoes) fprint(2, "\techo fd flush active\n");
		break;
	case Quit:
		if((ctlfd = open(ctlname, OWRITE)) >= 0){
			n = snprint(ctlbuf, sizeof(ctlbuf), "%s %s\n", cmdstr[cmd], basehub);
			if(write(ctlfd, ctlbuf, n) != n)
				warn("error writing to %s on fd[%d]: %r", ctlname, ctlfd);
			close(ctlfd);
		} else
			warn("can't open ctl file: %r");
		s->shellctl = 'q';
		freeshell(s);
		exits(nil);
	default:	/* no matching command found, print list of commands as reminder */
		warn("%% commands: \n\tdetach, remote NAME, local NAME, attach NAME \n\tstatus, list, err TIME, in TIME, out TIME\n\tfortun unfort echoes unecho trunc notrunc eof");
		return 0;
	}
	write(2, prompt, promptlen);
	return 1;
}

/* receive interrupt messages (delete key) and pass them through to attached shells */
int
sendinterrupt(void*, char *notename)
{
	char notehub[SMBUF];
	int notefd;

	if(strcmp(notename, "interrupt") != 0)
		return 0;
	notereceived = 1;
	snprint(notehub, sizeof(notehub), "%s/%s.note", mtpt, basehub);
	if((notefd = open(notehub, OWRITE)) < 0){
		warn("can't open %s", notehub);
		return 1;
	}
	write(notefd, notename, strlen(notename));
	close(notefd);
	return 1;
}

void
killfamily(void)
{
	if(cpid != -1){
		postnote(PNGROUP, cpid, "die");
		cpid = -1;
	}
}

void
main(int argc, char **argv)
{
	Shell *s;
	char *p;

	strcpy(shellname, "io");
	strcpy(srvname, "hubfs");
	ARGBEGIN{
	}ARGEND;
	switch(argc){
	case 2: strncpy(shellname, argv[1], sizeof(shellname));
	case 1: strncpy(srvname, argv[0], sizeof(srvname));
	case 0: break;
	default:
		fprint(2, "usage: %s [srvname [shellname]]\n", argv0);
		exits("usage");
	}

	notereceived = 0;
	fortunate = 0;
	echoes = 0;

	if(p = getenv("prompt"))
		prompt = p;
	promptlen = strlen(prompt);

	if((p = strrchr(srvname, '/')) == nil)
		p = srvname;
	else
		p++;
	snprint(mtpt, sizeof(mtpt), "/n/%s", p);
	snprint(ctlname, sizeof(ctlname), "%s/ctl", mtpt);

	if((s = setupshell(shellname)) == nil)
		sysfatal("setupshell() failed, bailing out");

	atnotify(sendinterrupt, 1);
	cpid = -1;
	atexit(killfamily);
	startshell(s);
}
