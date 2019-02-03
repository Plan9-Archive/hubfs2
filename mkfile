</$objtype/mkfile

BIN=/$objtype/bin
MAN=/sys/man/4

TARG=\
	hubfs\
	hubshell\

HFILES=\
	ratelimit.h\

</sys/src/cmd/mkmany

$O.hubfs: hubfs.$O ratelimit.$O
	$LD $LDFLAGS -o $target $prereq

$O.hubshell: hubshell.$O
	$LD $LDFLAGS -o $target $prereq

install:V: install.rc
	for (i in $TARG)
		mk $MKFLAGS $i.install

install.rc:V:
	if(! test -e /rc/bin/hub)
		cp hub.rc /rc/bin/hub
