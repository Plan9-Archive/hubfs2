#include <u.h>
#include <libc.h>
#include <auth.h>
#include <fcall.h>
#include <thread.h>
#include <9p.h>
#include <ctype.h>
#include "ratelimit.h"

/* input/output multiplexing and buferring */
/* often used in combination with hubshell client and hub wrapper script */

/* Flags track the state of queued 9p requests and ketchup/wait in paranoid mode */
enum flags{
	DOWN = 0,
	UP = 1,
	WAIT = 2,
	DONE = 3,
};

enum buffersizes{
	MAGIC = 77777,				/* In paranoid mode let readers lag this many bytes */
	MAXQ = 777,					/* Maximum number of 9p requests to queue */
	SMBUF = 777,				/* Buffer for names and other small strings */
	MAXHUBS = 77,				/* Total number of hubs that can be created */
};

typedef struct Hub	Hub;		/* A Hub file is a multiplexed pipe-like data buffer */
typedef struct Msgq	Msgq;		/* Client fid structure to track location */

struct Hub{
	char name[SMBUF];			/* name */
	char *bucket;				/* pointer to data buffer */
	char *inbuckp;				/* location to store next message */
	int buckfull;				/* amount of data stored in bucket */
	char *buckwrap;				/* exact limit of written data before pointer reset */
	Req *qreads[MAXQ];			/* pointers to queued read Reqs */
	int rstatus[MAXQ];			/* status of read requests */
	int qrnum;					/* index of read Reqs waiting to be filled */
	int qrans;					/* number of read Reqs answered */
	Req *qwrites[MAXQ];			/* Similar for write Reqs */
	int wstatus[MAXQ];
	int qwnum;
	int qwans;
	int ketchup;				/* lag of readers vs. writers in paranoid mode */
	int tomatoflag;				/* readers use tomatoflag to tell writers to wait */
	QLock wrlk;					/* writer lock during fear */
	QLock replk;				/* reply lock during fear */
	int killme;					/* forked processes in paranoid mode need to exit */
	Limiter *lp;				/* Pointer to limiter struct for this hub */
	vlong bp;					/* Bytes per second that can be written */
	vlong st;					/* minimum separation time between messages in ns */
	vlong rt;					/* Interval in seconds for resetting limit timer */
	Hub *next;					/* Next hub in list */
};

struct Msgq{
	ulong myfid;				/* Msgq is associated with client fids */
	char *nxt;					/* Location of this client in the buffer */
	int bufuse;					/* how much of the buffer has been used */
};

char *srvname;					/* Name of this hubfs service */
Hub *firsthub;
Hub *lasthub;
int nhubs;						/* Total number of hubs in existence */
int paranoia;					/* Paranoid mode maintains loose reader/writer sync */
int freeze;						/* In frozen mode the hubs operate simply as a ramfs */
int trunc;						/* In trunc mode only new data is sent, not buffered */
int allowzap;					/* Determine whether a buffer can be emptied forcibly */
int endoffile;					/* Send zero length end of file read to all clients */
int applylimits;				/* Whether time/rate limits are applied */
vlong bytespersecond;			/* Bytes per second allowed by rate limiting */
vlong separationinterval;		/* Minimum time between writes in nanoseconds */
vlong resettime;				/* Number of seconds between writes ratelimit reset */
u32int maxmsglen;				/* Maximum message length accepted */
uvlong bucksize;					/* Size of data bucket per hub */

static char Ebad[] = "something bad happened";
static char Ebadctl[] = "bad ctl message";
static char Enomem[] = "no memory";
static char Etoomany[] = "too many hubs";

void wrsend(Hub*);
void msgsend(Hub*);
char* hubctl(char*);
void setuphub(Hub*);
void addhub(Hub*);
void unlinkhub(Hub*);
char* eofhub(char*);
void hubqueue(Hub*, Req*);
int flushinated(Hub*, Req*);

void fsread(Req *r);
void fswrite(Req *r);
void fscreate(Req *r);
void fsopen(Req *r);
void fsflush(Req *r);
void fsdestroyfile(File *f);
void usage(void);

Srv fs = {
	.open = fsopen,
	.read = fsread,
	.write = fswrite,
	.create = fscreate,
	.flush = fsflush,
};

/*
 * Rate limiting is only applied if specified by flags.
 * The limiting parameters are global for the hubfs.
 * Each hubfile tracks its own limits separately.
*/

/*
 * Basic logic - we have a buffer/bucket of data (a hub) that is mapped to a file.
 * For each hub we keep two queues of 9p requests, one for reads and one for writes.
 * As requests come in, we add them to the queue, then fill waiting queued requests.
 * The data buffers are statically sized at creation. Data is continuously read
 * and written in a rotating pattern. At the end, we wrap back around to the start. 
 * Our job is accurately transferring the bytes in and out of the bucket and 
 * tracking the location of the read and write pointers for each writer and reader. 
*/

/* msgsend replies to Reqs queued by fsread */
void
msgsend(Hub *h)
{
	Req *r;
	Msgq *mq;
	u32int count;
	int i;

	if(h->qrnum == 0)
		return;

	/* loop through queued 9p read requests for this hub and answer if needed */
	for(i = h->qrans; i <= h->qrnum; i++){
		if(paranoia == UP)
			qlock(&h->replk);
		if(h->rstatus[i] != WAIT){
			if((i == h->qrans) && (i < h->qrnum))
				h->qrans++;
			if(paranoia == UP)
				qunlock(&h->replk);
			continue;
		}

		/* request found, if it has read all data keep it waiting unless eof sent */
		r = h->qreads[i];
		mq = r->fid->aux;
		if(mq->nxt == h->inbuckp){
			if(paranoia == UP)
				qunlock(&h->replk);
			if(endoffile == UP){
				r->ofcall.count = 0;
				h->rstatus[i] = DONE;
				if((i == h->qrans) && (i < h->qrnum))
					h->qrans++;
				respond(r, nil);
				continue;
			}
			continue;
		}
		count = r->ifcall.count;

		/* if the mq has read to the wrap point, send it back to start */
		if(mq->nxt >= h->buckwrap){
			mq->nxt = h->bucket;
			mq->bufuse = 0;
		}
		/* if the mq next read would go past wrap point, read up to wrap */
		if(mq->nxt + count > h->buckwrap)
			count = h->buckwrap - mq->nxt;
		/* if reader asks for more data than remains in bucket, adjust down */
		if((mq->bufuse + count > h->buckfull) && (mq->bufuse < h->buckfull))
			count = h->buckfull - mq->bufuse;

		/* Done with reader location and count checks, now we can send the data */
		memmove(r->ofcall.data, mq->nxt, count);
		r->ofcall.count = count;
		mq->nxt += count;
		mq->bufuse += count;
		h->rstatus[i] = DONE;
		if((i == h->qrans) && (i < h->qrnum))
			h->qrans++;
		respond(r, nil);

		if(paranoia == UP){
			h->ketchup = mq->bufuse;
			if(mq->bufuse <= h->buckfull)
				h->tomatoflag = DOWN;	/* DOWN means do not wait for us */
			else
				h->tomatoflag = UP;
			qunlock(&h->replk);
		}
	}
}

/* wrsend replies to Reqs queued by fswrite */
void
wrsend(Hub *h)
{
	Req *r;
	u32int count;
	int i;
	int j;

	if(h->qwnum == 0)
		return;

	/* in paranoid mode we fork and slack off while the readers catch up */
	if(paranoia == UP){
		qlock(&h->wrlk);
		if((h->ketchup < h->buckfull - MAGIC) || (h->ketchup > h->buckfull)){
			if(rfork(RFPROC|RFMEM) == 0){
				sleep(100);
				h->killme = UP;
				for(j = 0; ((j < 77) && (h->tomatoflag == UP)); j++)
					sleep(7);		/* Give readers time to catch up */
			} else
				return;	/* This branch should become a read request */
		}
	}

	/* loop through queued 9p write requests for this hub */
	for(i = h->qwans; i <= h->qwnum; i++){
		if(h->wstatus[i] != WAIT){
			if((i == h->qwans) && (i < h->qwnum))
				h->qwans++;
			continue;
		}
		r = h->qwrites[i];
		count = r->ifcall.count;
		if(count > maxmsglen)
			count = maxmsglen;

		/* bucket wraparound check */
		if((h->buckfull + count) >= bucksize - 16){
			h->buckwrap = h->inbuckp;
			h->inbuckp = h->bucket;
			h->buckfull = 0;
		}

		/* Move the data into the bucket, update our counters, and respond */
		memmove(h->inbuckp, r->ifcall.data, count);
		h->inbuckp += count;
		if(h->inbuckp > h->buckwrap)
			h->buckwrap=h->inbuckp+1;
		h->buckfull += count;
		r->fid->file->length = h->buckfull;
		r->ofcall.count = count;
		h->wstatus[i] = DONE;
		if((i == h->qwans) && (i < h->qwnum))
			h->qwans++;
		if(applylimits)
			limit(h->lp, count);
		respond(r, nil);

		if(paranoia == UP){
			if(h->wrlk.locked == 1)
				qunlock(&h->wrlk);
			/* If killme is up we forked another flow of control, so exit */
			if(h->killme == UP){
				h->killme = DOWN;
				exits(nil);
			}
		}
	}
}

void
hubqueue(Hub *h, Req *r)
{
	if(h->qrnum >= MAXQ-2){
		memmove(h->qreads+1, h->qreads+h->qrans, h->qrnum - h->qrans);
		memmove(h->rstatus+1, h->rstatus+h->qrans, h->qrnum - h->qrans);
		h->qrnum = h->qrnum - h->qrans + 1;
		h->qrans = 1;
	}
	h->qrnum++;
	h->rstatus[h->qrnum] = WAIT;
	h->qreads[h->qrnum] = r;
}

/* queue all reads unless Hubs are set to freeze */
void
fsread(Req *r)
{
	char *err;
	Hub *h;
	Msgq *mq;
	u32int count, n;
	vlong offset;
	char tmpstr[2*SMBUF];

	h = r->fid->file->aux;
	err = nil;
	if(strncmp(h->name, "ctl", 3) == 0){
		if(r->ifcall.offset > 0){
			r->ofcall.count = 0;
		done:
			respond(r, err);
			return;
		}
		snprint(tmpstr, sizeof(tmpstr),
			"\tHubfs %s status (1 is active, 0 is inactive):\n"
			"Paranoia == %d  Freeze == %d  Trunc == %d  Applylimits == %d\n"
			"Buffersize == %ulld\n"
			, srvname, paranoia, freeze, trunc, applylimits, bucksize);
		if((n = strlen(tmpstr)) > r->ifcall.count){
			err = "read too small for response";
			goto done;
		}
		memmove(r->ofcall.data, tmpstr, n);
		r->ofcall.count = n;
		goto done;
	}

	/* In freeze mode hubs behave as ramdisk files */
	if(freeze == UP){
		mq = r->fid->aux;
		if(mq->bufuse > 0){
			hubqueue(h, r);
			return;
		}
		count = r->ifcall.count;
		offset = r->ifcall.offset;
		while(offset >= bucksize)
			offset -= bucksize;
		if(offset >= h->buckfull){
			r->ofcall.count = 0;
			goto done;
		}
		if((offset + count >= h->buckfull) && (offset < h->buckfull))
			count = h->buckfull - offset;
		memmove(r->ofcall.data, h->bucket + offset, count);
		r->ofcall.count = count;
		goto done;
	}

	hubqueue(h, r);
	msgsend(h);
}

/* queue writes unless hubs are set to frozen mode */
void
fswrite(Req *r)
{
	char *err;
	Hub *h;
	u32int count;
	vlong offset;
	int i, j;

	h = r->fid->file->aux;
	err = nil;
	if(strncmp(h->name, "ctl", 3) == 0){
		err = hubctl(r->ifcall.data);
	done:
		respond(r, err);
		return;
	} else if(freeze == UP){
		count = r->ifcall.count;
		offset = r->ifcall.offset;
		while(offset >= bucksize)
			offset -= bucksize;
		h->inbuckp = h->bucket +offset;
		h->buckfull = h->inbuckp - h->bucket;
		if(h->buckfull + count >= bucksize){
			h->inbuckp = h->bucket;
			h->buckfull = 0;
		}
		memmove(h->inbuckp, r->ifcall.data, count);
		h->inbuckp += count;
		h->buckfull += count;
		r->fid->file->length = h->buckfull;
		r->ofcall.count = count;
		goto done;
	}

	/* Actual queue logic here */
	if(h->qwnum >= MAXQ - 2){
		j = 1;
		for(i = h->qwans; i <= h->qwnum; i++) {
			h->qwrites[j] = h->qwrites[i];
			h->wstatus[j] = h->wstatus[i];
			j++;
		}
		h->qwnum = h->qwnum - h->qwans + 1;
		h->qwans = 1;
	}
	h->qwnum++;
	h->wstatus[h->qwnum] = WAIT;
	h->qwrites[h->qwnum] = r;
	wrsend(h);
	msgsend(h);
	/* we do msgsend here after wrsend because we know a write has happened */
	/* that means there is new data for readers, so send it to them asap */
}

/* making a file is making a new hub, prepare it for i/o and add to hublist */
void
fscreate(Req *r)
{
	Hub *h;
	File *f;
	char *err;

	err = nil;
	if(nhubs >= MAXHUBS){
		err = Etoomany;
	} else if(f = createfile(r->fid->file, r->ifcall.name, r->fid->uid, r->ifcall.perm, nil)){
		nhubs++;
		h = emalloc9p(sizeof(*h));
		setuphub(h);
		lasthub->next = h;
		lasthub = h;
		strncat(h->name, r->ifcall.name, SMBUF);
		f->aux = h;
		r->fid->file = f;
		r->ofcall.qid = f->qid;
	} else
		err = Ebad;

	respond(r, err);
}

/* new client for the hubfile, create new message queue with client fid */
void
fsopen(Req *r)
{
	Hub *h;
	Msgq *q;

	h = r->fid->file->aux;
	if(!h){
		respond(r, nil);
		return;
	}
	q = emalloc9p(sizeof(*q));

	q->myfid = r->fid->fid;
	q->nxt = h->bucket;
	q->bufuse = 0;
	if(r->ifcall.mode&OTRUNC){
		if(allowzap){
			h->inbuckp = h->bucket;
			h->buckfull = 0;
			r->fid->file->length = 0;
		}
	}
	if (trunc == UP){
		q->nxt = h->inbuckp;
		q->bufuse = h->buckfull;
	}
	r->fid->aux = q;
	respond(r, nil);
}

/* flush a pending request if the client asks us to */
void
fsflush(Req *r)
{
	Hub *h;

	for(h = firsthub->next; h != nil; h = h->next)
		if(flushinated(h, r))
			return;

	respond(r, nil);
}

/* check a hub to see if it contains a pending Req with matching tag */
int
flushinated(Hub *h, Req *r)
{
	Req *tr;
	int i;

	for(i = h->qrans; i <= h->qrnum; i++){
		if(h->rstatus[i] != WAIT)
			continue;
		tr=h->qreads[i];
		if(tr->tag == r->ifcall.oldtag){
			tr->ofcall.count = 0;
			h->rstatus[i] = DONE;
			if((i == h->qrans) && (i < h->qrnum))
				h->qrans++;
			respond(tr, nil);
			respond(r, nil);
			return 1;
		}
	}
	for(i = h->qwans; i <= h->qwnum; i++){
		if(h->wstatus[i] != WAIT)
			continue;
		tr=h->qwrites[i];
		if(tr->tag == r->ifcall.oldtag){
			tr->ofcall.count = 0;
			h->wstatus[i] = DONE;
			if((i == h->qwans) && (i < h->qwnum))
				h->qwans++;
			respond(tr, nil);
			respond(r, nil);
			return 1;
		}
	}
	return 0;
}

/* delete the hub. We don't track the associated mqs of clients so we leak them. */
void
fsdestroyfile(File *f)
{
	Hub *h;

	if(h = f->aux){
		nhubs--;
		unlinkhub(h);
		if(h->lp)
			free(h->lp);
		free(h->bucket);
		free(h);
	}
}

/* called when a hubfile is created */
/* ?Why is qrans set to 1 and qwans to 0 when both are set to 1 upon looping? */
void
setuphub(Hub *h)
{
	h->bucket = emalloc9p(bucksize);
	h->inbuckp = h->bucket;
	h->qrnum = 0;
	h->qrans = 1;
	h->qwnum = 0;
	h->qwans = 0;
	h->ketchup = 0;
	h->buckfull = 0;
	h->buckwrap = h->inbuckp + bucksize;
	if(applylimits){
		h->bp = bytespersecond;
		h->st = separationinterval;
		h->rt = resettime;
		h->lp = startlimit(SECOND/h->bp, h->st, h->rt * SECOND);
	}
}

/* remove a hub about to be deleted from the linked list of hubs */
void
unlinkhub(Hub *th)
{
	Hub *h, *lh;

	lh = nil;
	h = firsthub;
	while(h != nil && h != th){
		lh = h;
		h = h->next;
	}

	if(h == th)
		lh->next = h->next;
}

enum{
	Calm,
	Fear,
	Freeze,
	Melt,
	Trunc,
	Notrunc,
	Eof,
	Quit,
	NCmd,
};

char *cmdstr[] = {
	[Quit] = "quit",
	[Fear] = "fear",
	[Calm] = "calm",
	[Freeze] = "freeze",
	[Melt] = "melt",
	[Trunc] = "trunc",
	[Notrunc] = "notrunc",
	[Eof] = "eof",
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

/* issue eofs or set status of paranoid mode and frozen/normal from ctl messages */
char*
hubctl(char *buf)
{
	int cmd, cmdlen;
	char *p, *q;

	cmd = getcmd(buf);
	if(cmd != NCmd){
		if(p = strchr(buf, '\n'))
			*p = '\0';
		cmdlen = strlen(cmdstr[cmd]);
		p = buf+cmdlen;
		if(*p != '\0'){
			while(*p == ' ' || *p == '\t')
				p++;
			if(*p != '\0'){
				if(q = strstr(p, " \t"))
					*q = '\0';
			} else
				p = nil;
		} else
			p = nil;
	} else
		p = nil;
	switch(cmd){
	case Calm: paranoia = DOWN; break;
	case Fear: paranoia = UP; break;
	case Freeze: freeze = UP; break;
	case Melt: freeze = DOWN; break;
	case Trunc: trunc = UP; break;
	case Notrunc: trunc = DOWN; break;
	case Quit: exits("");
	case Eof: return eofhub(p);
	default:
		return Ebadctl;
	}
	return nil;
}

/* send eof to specific named hub */
char*
eofhub(char *s){
	Hub *h;
	char *err;

	fprint(2, "eof: %s\n", s);
	err = nil;
	endoffile = UP;
	for(h = firsthub; h != nil; h = h->next){
		if(s != nil){
			if(strcmp(s, h->name) == 0){
				msgsend(h);
				break;
			}
		} else
			msgsend(h);
	}
	if(h == nil && s != nil)
		err = "hub not found";

	endoffile = DOWN;
	return err;
}

void
usage(void)
{
	fprint(2,
		"usage: %s [-Dtz] [-q bktsize] [-b B/s]"
		" [-i nsmsg] [-r timerreset] [-l maxmsglen]"
		" [-s srvname] [-m mtpt]\n"
		, argv0);
	exits("usage");
}

long
estrtol(char *as, char **aas, int base)
{
	long n;
	char *p;

	n = strtol(as, &p, base);
	if(p == as)
		sysfatal("estrtol: bad input '%s'", as);
	else if(aas != nil)
		*aas = p;

	return n;
}

uvlong
estrtoull(char *as, char **aas, int base)
{
	uvlong n;
	char *p;

	n = strtoull(as, &p, base);
	if(p == as)
		sysfatal("estrtoull: bad input '%s'", as);
	else if(aas != nil)
		*aas = p;

	return n;
}

void
main(int argc, char **argv)
{
	int fd;
	char *addr;
	char *mtpt;
	char *bps, *rst, *len, *spi, *qua;

	paranoia = DOWN;
	freeze = DOWN;
	trunc = DOWN;
	allowzap = DOWN;
	endoffile = DOWN;
	applylimits = DOWN;
	nhubs = 0;
	bytespersecond = 1024*1024*1024;
	separationinterval = 1;
	resettime =  60;
	maxmsglen = 666666;
	bucksize = 777777;

	fs.tree = alloctree(nil, nil, DMDIR|0777, fsdestroyfile);

	addr = nil;
	mtpt = nil;
	srvname = nil;
	ARGBEGIN{
	case 'D':
		chatty9p++;
		break;
	case 'q':
		qua = EARGF(usage());
		bucksize = estrtoull(qua, 0 , 10);
		break;
	case 'b':
		bps = EARGF(usage());
		bytespersecond = estrtoull(bps, 0, 10);
		applylimits = UP;
		break;
	case 'i':
		spi = EARGF(usage());
		separationinterval = estrtoull(spi, 0, 10);
		applylimits = UP;
		break;
	case 'r':
		rst = EARGF(usage());
		resettime = estrtoull(rst, 0, 10);
		applylimits = UP;
		break;
	case 'l':
		len = EARGF(usage());
		maxmsglen = estrtol(len, 0, 10);
		break;
	case 'a':
		addr = EARGF(usage());
		break;
	case 's':
		srvname = EARGF(usage());
		break;
	case 'm':
		mtpt = EARGF(usage());
		break;
	case 't':
		trunc = UP;
		break;
	case 'z':
		allowzap = UP;
		break;
	default:
		usage();
	}ARGEND;
	if(argc)
		usage();
	if(chatty9p)
		fprint(2, "hubsrv.nopipe %d srvname %s mtpt %s\n", fs.nopipe, srvname, mtpt);
	if(addr == nil && srvname == nil && mtpt == nil)
		sysfatal("must specify -a, -s, or -m option");

	/* start with an allocated but empty Hub */
	firsthub = emalloc9p(sizeof(*firsthub));
	lasthub = firsthub;

	close(0);
	if((fd = open("/dev/null", ORDWR)) != 0)
		sysfatal("open returned %d: %r", fd);
	if((fd = dup(0, 1)) != 1)
		sysfatal("dup returned %d: %r", fd);

	if(addr)
		listensrv(&fs, addr);
	if(srvname || mtpt)
		postmountsrv(&fs, srvname, mtpt, MREPL|MCREATE);
	exits(0);
}

/* basic 9pfile implementation taken from /sys/src/lib9p/ramfs.c */

/* A note on paranoid mode and writer/reader synchronization.  The
default behavior is "broadcast like" rather than pipelike, because
writers are never blocked by default.  This is because in a network
situation with remote readers, blocking writes to wait for remote
client reads to complete produces an unpleasant user experience where
the remote latency limits the local environment.  As a consequence, by
default it is up to the writer to a file to limit the quantity and
speed of data writen to what clients are able receive.  The normal
intended mode of operation is for shells, and in this case data is
both 'bursty' and usually fairly small.  */

/* Paranoid mode is intended as "safe mode" and changes this
first-come first served behavior.  In paranoid mode, the readers and
writers attempt to synchronize.  The hub ketchup and tomatoflag
variables are used to monitor if readers have 'fallen behind' the
current data pointer, and if so, the writer is qlocked and sleeps
while we fork off a new flow of control.  We need to do more than just
answer the queued reads - because we are inside the 9p library (we are
the functions called by its srv pointer) we want the 9p library to
actually answer the incoming reads so we have read messages queued to
answer.  Just clearing out the read message queue isn't enough to
prioritize readers - we need to fork off so the controlling 9p library
has a chance to answer NEW reads.  By forking and sleeping the writer,
we allow the os to answer a new read request, which will unlock the
writer, which then needs to die at the end of its function because we
are a single-threaded 9p server and need to maintain one master flow
of control.  */

/* The paranoid/safe mode code is still limited in its logic for
handling multiple readers.  The ketchup and tomatoflag are per hub,
and a hub can have multiple clients.  It is intentional that these
multiple clients will 'race for the flag' and the writer will stop
waiting when one reader catches up enough to set ketchup and tomato
flag.  A more comprehensive solution would require adding new
structure to the client mq and a ref-counting implementation for
attaches to the hub so the hub could check the status of each client
individually.  There are additional problems with this because clients
are free to 'stop reading' at any time and thus a single client
unattaching will end up forcing the hub into 'as slow as possible'
mode.  */

/* To avoid completely freezing a hub, there is still a default "go
ahead" time even when clients have not caught up.  This time is
difficult to assess literally because it is a repeated sleep loop so
the os may perform many activities during the sleep.  Extending the
length of this delay time increases the safety guarantee for lagging
clients, but also increases the potential for lag and for
molasses-like shells after remote clients disconnect.  */

/* In general for the standard use of interactive shells paranoid mode
is unnecessary and all of this can and should be ignored.  For data
critical applications aiming for high speed constant throughput,
paranoid mode can and should be used, but additional data
verification, such as a cryptographic hashing protocol, would still be
recommended.  */
